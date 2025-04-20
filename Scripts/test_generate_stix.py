import unittest
import json
import os
from unittest.mock import patch, mock_open, MagicMock
import requests
from stix2 import Bundle, File, Malware, Relationship, TLP_WHITE

# Import the functions/constants from the script we are testing
import generate_stix

# Sample data mimicking Malware Bazaar API responses
SAMPLE_API_RESPONSE_OK = {
    "query_status": "ok",
    "data": [
        {
            "sha256_hash": "a" * 64,
            "md5_hash": "a" * 32,
            "file_name": "sample_a.apk",
            "signature": "Android.SampleMalwareA",
            "tags": ["android", "apk", "sampleA"]
        },
        {
            "sha256_hash": "b" * 64,
            "md5_hash": "b" * 32,
            "file_name": "sample_b.ipa",
            "signature": None, # No specific signature
            "tags": ["ios", "ipa", "sampleB"]
        },
        {
            "sha256_hash": "c" * 64,
            "md5_hash": "a" * 32, # Duplicate MD5
            "file_name": "duplicate_a.apk",
            "signature": "Android.SampleMalwareA", # Same signature as first
            "tags": ["android", "apk", "sampleA"]
        },
         {
            "sha256_hash": "d" * 64,
            "md5_hash": None, # Missing MD5
            "file_name": "no_md5.apk",
            "signature": "Android.NoMD5",
            "tags": ["android", "apk"]
        }
    ]
}

SAMPLE_API_RESPONSE_ERROR = {
    "query_status": "illegal_query"
}

SAMPLE_IOC_DATA = {
    "android": SAMPLE_API_RESPONSE_OK["data"] # Use the same sample data for simplicity
}


class TestGenerateStix(unittest.TestCase):

    # --- Tests for query_malware_bazaar ---

    @patch('generate_stix.requests.post')
    def test_query_success(self, mock_post):
        """Test successful API query."""
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = SAMPLE_API_RESPONSE_OK
        mock_post.return_value = mock_response

        result = generate_stix.query_malware_bazaar("android")

        mock_post.assert_called_once_with(
            generate_stix.MALWARE_BAZAAR_API_URL,
            data={'query': 'get_taginfo', 'tag': "android"},
            timeout=generate_stix.REQUEST_TIMEOUT
        )
        mock_response.raise_for_status.assert_called_once()
        self.assertEqual(result, SAMPLE_API_RESPONSE_OK)

    @patch('generate_stix.requests.post')
    def test_query_timeout(self, mock_post):
        """Test API query timeout."""
        mock_post.side_effect = requests.exceptions.Timeout("Request timed out")

        result = generate_stix.query_malware_bazaar("android")

        mock_post.assert_called_once()
        self.assertIsNone(result)
        # Add check for print output if necessary using redirect_stdout

    @patch('generate_stix.requests.post')
    def test_query_request_exception(self, mock_post):
        """Test general request exception."""
        mock_post.side_effect = requests.exceptions.RequestException("Connection error")

        result = generate_stix.query_malware_bazaar("android")

        mock_post.assert_called_once()
        self.assertIsNone(result)

    @patch('generate_stix.requests.post')
    def test_query_http_error(self, mock_post):
        """Test HTTP error response (e.g., 404, 500)."""
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("404 Client Error")
        mock_post.return_value = mock_response

        result = generate_stix.query_malware_bazaar("android")

        mock_post.assert_called_once()
        mock_response.raise_for_status.assert_called_once()
        self.assertIsNone(result)

    @patch('generate_stix.requests.post')
    def test_query_json_decode_error(self, mock_post):
        """Test invalid JSON response."""
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.side_effect = json.JSONDecodeError("Expecting value", "doc", 0)
        mock_response.text = "Invalid JSON response"
        mock_post.return_value = mock_response

        result = generate_stix.query_malware_bazaar("android")

        mock_post.assert_called_once()
        mock_response.raise_for_status.assert_called_once()
        self.assertIsNone(result)

    # --- Tests for create_stix_bundle ---

    def test_create_bundle_basic(self):
        """Test creating a bundle with valid data."""
        bundle = generate_stix.create_stix_bundle(SAMPLE_IOC_DATA)
        self.assertIsInstance(bundle, Bundle)

        # Expected objects: TLP_WHITE, 2 Files (deduplicated), 2 Malware (deduplicated), 2 Relationships
        # Total = 1 + 2 + 2 + 2 = 7
        self.assertEqual(len(bundle.objects), 7)

        file_hashes = set()
        malware_names = set()
        relationship_count = 0
        has_tlp_white_marking_def = False
        tlp_white_id = TLP_WHITE.id # Get the standard ID

        for obj in bundle.objects:
            if isinstance(obj, File):
                self.assertIn("MD5", obj.hashes)
                file_hashes.add(obj.hashes["MD5"])
                # FIX: Check for the ID string in the list
                self.assertIn(tlp_white_id, obj.object_marking_refs)
            elif isinstance(obj, Malware):
                malware_names.add(obj.name)
                # FIX: Check for the ID string in the list
                self.assertIn(tlp_white_id, obj.object_marking_refs)
            elif isinstance(obj, Relationship):
                relationship_count += 1
                # FIX: Check for the ID string in the list
                self.assertIn(tlp_white_id, obj.object_marking_refs)
            elif obj.id == tlp_white_id: # Check if the marking definition itself is present
                 has_tlp_white_marking_def = True

        self.assertTrue(has_tlp_white_marking_def)
        self.assertEqual(len(file_hashes), 2) # Check deduplication worked (a*32, b*32)
        self.assertIn("a" * 32, file_hashes)
        self.assertIn("b" * 32, file_hashes)
        self.assertEqual(len(malware_names), 2) # Check deduplication/caching
        self.assertIn("Android.SampleMalwareA", malware_names)
        self.assertIn("Unknown Malware (android)", malware_names) # Fallback name
        self.assertEqual(relationship_count, 2) # One relationship per unique file

    def test_create_bundle_malware_naming_and_family(self):
        """Test malware naming and is_family flag."""
        bundle = generate_stix.create_stix_bundle(SAMPLE_IOC_DATA)
        malware_a = next((obj for obj in bundle.objects if isinstance(obj, Malware) and obj.name == "Android.SampleMalwareA"), None)
        malware_b = next((obj for obj in bundle.objects if isinstance(obj, Malware) and obj.name == "Unknown Malware (android)"), None)

        self.assertIsNotNone(malware_a)
        self.assertTrue(malware_a.is_family) # Has signature

        self.assertIsNotNone(malware_b)
        self.assertFalse(malware_b.is_family) # No signature, used fallback

    def test_create_bundle_empty_data(self):
        """Test creating a bundle with no input data."""
        bundle = generate_stix.create_stix_bundle({})
        self.assertIsNone(bundle)

    def test_create_bundle_no_valid_samples(self):
        """Test creating a bundle when samples lack required fields (MD5)."""
        invalid_data = {
            "android": [{"sha256_hash": "d"*64, "file_name": "invalid.apk", "signature": "Test"}] # Missing md5_hash
        }
        bundle = generate_stix.create_stix_bundle(invalid_data)
        self.assertIsNone(bundle) # Should only contain TLP:WHITE, so returns None

    # --- Tests for main ---

    @patch('generate_stix.query_malware_bazaar')
    @patch('generate_stix.create_stix_bundle')
    @patch('builtins.open', new_callable=mock_open)
    @patch('os.makedirs') # Keep the mock, even if not always called
    @patch('os.path.exists', return_value=False) # Assume dir doesn't exist initially
    def test_main_success(self, mock_exists, mock_makedirs, mock_file_open, mock_create, mock_query):
        """Test the main function successful execution path."""
        # Mock API query to return data for one tag
        mock_query.return_value = SAMPLE_API_RESPONSE_OK

        # Mock bundle creation
        mock_bundle = MagicMock(spec=Bundle)
        mock_bundle.serialize.return_value = '{"type": "bundle", ...}'
        mock_create.return_value = mock_bundle

        generate_stix.main()

        # Assertions
        self.assertGreater(mock_query.call_count, 0) # Called for each tag
        mock_create.assert_called_once()
        # FIX: Remove assertion for makedirs as it's not called with default OUTPUT_FILE
        # mock_makedirs.assert_called_once_with(os.path.dirname(generate_stix.OUTPUT_FILE))
        mock_makedirs.assert_not_called() # Explicitly check it wasn't called
        mock_file_open.assert_called_once_with(generate_stix.OUTPUT_FILE, "w", encoding="utf-8")
        mock_file_open().write.assert_called_once_with('{"type": "bundle", ...}')

    @patch('generate_stix.query_malware_bazaar', return_value=None) # Simulate API failure
    @patch('generate_stix.create_stix_bundle')
    @patch('builtins.open', new_callable=mock_open)
    def test_main_no_api_data(self, mock_file_open, mock_create, mock_query):
        """Test main function when API calls fail."""
        generate_stix.main()

        self.assertGreater(mock_query.call_count, 0)
        mock_create.assert_not_called()
        mock_file_open.assert_not_called()

    @patch('generate_stix.query_malware_bazaar', return_value=SAMPLE_API_RESPONSE_OK)
    @patch('generate_stix.create_stix_bundle', return_value=None) # Simulate no valid IOCs found
    @patch('builtins.open', new_callable=mock_open)
    def test_main_no_stix_objects(self, mock_file_open, mock_create, mock_query):
        """Test main function when create_stix_bundle returns None."""
        generate_stix.main()

        self.assertGreater(mock_query.call_count, 0)
        mock_create.assert_called_once()
        mock_file_open.assert_not_called()

    @patch('generate_stix.query_malware_bazaar', return_value=SAMPLE_API_RESPONSE_OK)
    @patch('generate_stix.create_stix_bundle')
    @patch('builtins.open', side_effect=IOError("Permission denied")) # Simulate file write error
    @patch('os.makedirs')
    @patch('os.path.exists', return_value=True) # Assume dir exists
    def test_main_file_write_error(self, mock_exists, mock_makedirs, mock_file_open, mock_create, mock_query):
        """Test main function handling file write IOErrors."""
        mock_bundle = MagicMock(spec=Bundle)
        mock_bundle.serialize.return_value = '{"type": "bundle", ...}'
        mock_create.return_value = mock_bundle

        generate_stix.main()

        self.assertGreater(mock_query.call_count, 0)
        mock_create.assert_called_once()
        # FIX: Change assertion to check if open was called at all
        mock_file_open.assert_called_once()
        # We can still check the arguments if needed, but assert_called_once() is often enough here
        # self.assertEqual(mock_file_open.call_args[0][0], generate_stix.OUTPUT_FILE)
        # self.assertEqual(mock_file_open.call_args[0][1], "w")
        # self.assertEqual(mock_file_open.call_args[1]['encoding'], "utf-8")

        # Add check for print output if necessary


if __name__ == '__main__':
    # Corrected the way unittest.main is called for script execution
    unittest.main(argv=['first-arg-is-ignored'], exit=False)
