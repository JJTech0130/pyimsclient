"""
Download and parse Apple carrier bundles to extract carrier.plist files.
"""
import sys
import plistlib
import requests
import zipfile
from io import BytesIO
try:
    from rich import print
except ImportError:
    print=print


APPLE_MASTER_PLIST_URL = "https://itunes.apple.com/WebObjects/MZStore.woa/wa/com.apple.jingle.appserver.client.MZITunesClientCheck/version?languageCode=en"


def get_master_list():
    """Download Apple's master carrier plist."""
    response = requests.get(APPLE_MASTER_PLIST_URL, timeout=15)
    response.raise_for_status()
    return plistlib.loads(response.content)


def _is_float(value):
    """Return True if convertible to float."""
    try:
        float(value)
        return True
    except Exception:
        return False


def get_bundle_by_name(bundle_name, master_plist):
    """Fetch the bundle binary for a given bundle name."""
    bundles = master_plist.get("MobileDeviceCarrierBundlesByProductVersion", {})
    if bundle_name not in bundles:
        return None

    versions = bundles[bundle_name]
    valid_versions = [v for v in versions if _is_float(v)]
    if not valid_versions:
        return None

    latest_ver = max(valid_versions, key=float)
    url = versions[latest_ver]["BundleURL"]

    response = requests.get(url, timeout=15)
    response.raise_for_status()
    return response.content


def get_bundles_for_mccmnc(mccmnc, master_plist, mvno=False):
    """Return all relevant bundle names and their data for a given MCC/MNC."""
    carriers = master_plist.get("MobileDeviceCarriersByMccMnc", {})
    carrier_data = carriers.get(mccmnc)
    if not carrier_data:
        return None

    bundles = []

    # Primary bundle
    if "BundleName" in carrier_data:
        bundles.append(carrier_data["BundleName"])

    if mvno:
        # MVNO bundles
        for mvno in carrier_data.get("MVNOs", []):
            if "BundleName" in mvno:
                bundles.append(mvno["BundleName"])

    return bundles or None


def parse_bundle(bundle_bytes):
    """Extract and parse the carrier.plist from a zipped carrier bundle."""
    with zipfile.ZipFile(BytesIO(bundle_bytes)) as zf:
        carrier_path = next(
            (p for p in zf.namelist()
             if p.startswith("Payload/") and p.endswith("/carrier.plist")),
            None,
        )
        if not carrier_path:
            raise FileNotFoundError("carrier.plist not found in bundle.")
        return plistlib.load(zf.open(carrier_path))


def fetch_carrier_plist_by_bundle(bundle_name, master_plist):
    """Fetch and return the carrier.plist for a specific bundle name."""
    bundle_bytes = get_bundle_by_name(bundle_name, master_plist)
    if not bundle_bytes:
        raise ValueError(f"No bundle found with name: {bundle_name}")
    return parse_bundle(bundle_bytes)


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        sys.exit(1)

    identifier = argv[1]
    mvno = "--mvno" in argv

    try:
        master_plist = get_master_list()

        # Case 1: MCCMNC input
        if identifier.isdigit():
            bundle_names = get_bundles_for_mccmnc(identifier, master_plist, mvno=mvno)
            if not bundle_names:
                raise ValueError(f"No bundles found for MCC/MNC {identifier}")

            # Multiple bundles: just list them
            if len(bundle_names) > 1:
                print(f"Multiple bundles found for MCC/MNC {identifier}:")
                for name in bundle_names:
                    print(f"  - {name}")
                sys.exit(0)

            # Single bundle → fetch carrier.plist
            carrier_plist = fetch_carrier_plist_by_bundle(bundle_names[0], master_plist)

        # Case 2: Bundle name input
        else:
            carrier_plist = fetch_carrier_plist_by_bundle(identifier, master_plist)

        print(carrier_plist)

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv)
