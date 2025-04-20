#!/usr/bin/env python3
import requests
import json
import os
from datetime import datetime, timezone
import uuid  # Add this import at the top of the file
# Make sure to install stix2: pip install stix2 requests
# Import the standard TLP_WHITE constant directly
from stix2 import Bundle, File, Malware, Relationship, TLP_WHITE, MarkingDefinition, Indicator

__version__ = "1.2" # Incremented version

MALWARE_BAZAAR_API_URL = "https://mb-api.abuse.ch/api/v1/"
# Tags relevant to mobile platforms
SEARCH_TAGS = ["android", "ios", "apk", "ipa"]
OUTPUT_FILE = "todas_as_letras_mobile_iocs.stix2"
REQUEST_TIMEOUT = 45 # Increased timeout for potentially large responses

# TLP:WHITE marking definition (standard for public sharing) - NO LONGER NEEDED TO CREATE MANUALLY
# TLP_WHITE_MARKING = MarkingDefinition(
#     definition_type="tlp",
#     definition={"tlp": "white"}
# )

def query_malware_bazaar(tag):
    """Queries Malware Bazaar API for samples associated with a specific tag."""
    print(f"[*] Querying Malware Bazaar for tag: {tag}...")
    data = {'query': 'get_taginfo', 'tag': tag}
    try:
        response = requests.post(MALWARE_BAZAAR_API_URL, data=data, timeout=REQUEST_TIMEOUT)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        print(f"[+] Successfully retrieved data for tag: {tag}")
        return response.json()
    except requests.exceptions.Timeout:
        print(f"[!] Timeout error querying Malware Bazaar for tag {tag}.")
    except requests.exceptions.RequestException as e:
        print(f"[!] Error querying Malware Bazaar for tag {tag}: {e}")
    except json.JSONDecodeError:
        # Added check for response variable existence before accessing .text
        response_text = response.text[:200] if 'response' in locals() and hasattr(response, 'text') else "N/A"
        print(f"[!] Error decoding JSON response for tag {tag}. Response text: {response_text}...")
    return None

def get_stix_timestamp():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

def create_stix_bundle(ioc_data):
    """Creates a STIX 2.1 bundle from the collected IOC data."""
    stix_objects = [TLP_WHITE]  # Include the standard marking definition
    malware_objects_cache = {}  # Cache Malware SDOs to avoid duplicates based on name

    for tag, samples in ioc_data.items():
        print(f"[*] Processing {len(samples)} samples for tag: {tag}")
        for sample in samples:
            md5_hash = sample.get('md5_hash')
            file_name = sample.get('file_name')
            signature = sample.get('signature')  # Main classification/name from MB
            tags = sample.get('tags', [])  # Additional context tags

            if not md5_hash:
                continue

            # --- Create Indicator Object ---
            pattern = f"[file:hashes.md5 = '{md5_hash}']"
            indicator = Indicator(
                id=f"indicator--{uuid.uuid4()}",  # Generate a valid UUID for the ID
                created=get_stix_timestamp(),
                modified=get_stix_timestamp(),
                name=f"Indicator for {file_name or 'unknown file'}",
                description=f"Indicator for file with MD5 hash {md5_hash}",
                pattern=pattern,
                pattern_type="stix",
                pattern_version="2.1",
                indicator_types=["malicious-activity"],
                valid_from=get_stix_timestamp(),
                object_marking_refs=[TLP_WHITE]
            )
            stix_objects.append(indicator)

            # --- Create Malware Object ---
            malware_name = signature if signature else f"Unknown Malware ({tag})"
            malware_id_key = malware_name.lower()

            if malware_id_key not in malware_objects_cache:
                malware_obj = Malware(
                    name=malware_name,
                    is_family=False,
                    description=f"Malware identified by Malware Bazaar. Associated tags: {', '.join(tags)}.",
                    object_marking_refs=[TLP_WHITE]
                )
                stix_objects.append(malware_obj)
                malware_objects_cache[malware_id_key] = malware_obj
            else:
                malware_obj = malware_objects_cache[malware_id_key]

            # --- Create Relationship ---
            relationship = Relationship(
                source_ref=indicator.id,
                relationship_type="indicates",
                target_ref=malware_obj.id,
                description=f"Indicator '{indicator.name}' indicates malware '{malware_name}'.",
                object_marking_refs=[TLP_WHITE]
            )
            stix_objects.append(relationship)

    if len(stix_objects) <= 1:  # Only contains the marking definition
        print("[!] No valid STIX objects created.")
        return None

    # Create the final bundle
    bundle = Bundle(objects=stix_objects, allow_custom=False)
    print(f"[+] Created STIX bundle with {len(stix_objects)} total objects.")
    return bundle

def main():
    """Main function to query API and generate STIX file."""
    all_ioc_data = {}
    print("[*] Starting IOC collection from Malware Bazaar...")
    for tag in SEARCH_TAGS:
        result = query_malware_bazaar(tag)
        if result and result.get('query_status') == 'ok' and result.get('data'):
            all_ioc_data[tag] = result['data']
        elif result:
            print(f"[-] Malware Bazaar query for tag '{tag}' did not return 'ok' status or data: {result.get('query_status')}")
        else:
            print(f"[-] Failed to retrieve data for tag '{tag}'.")

    if not all_ioc_data:
        print("[!] No data successfully retrieved from Malware Bazaar for any tag. Exiting.")
        return

    stix_bundle = create_stix_bundle(all_ioc_data)

    if stix_bundle:
        try:
            print(f"[*] Writing STIX data to {OUTPUT_FILE}...")
            output_dir = os.path.dirname(OUTPUT_FILE)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)

            with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
                f.write(stix_bundle.serialize(pretty=True))
            print(f"[+] Successfully wrote STIX data to {OUTPUT_FILE}")
        except IOError as e:
            print(f"[!] Error writing STIX file {OUTPUT_FILE}: {e}")
        except Exception as e:
            print(f"[!] An unexpected error occurred during file writing: {e}")

if __name__ == "__main__":
    main()
