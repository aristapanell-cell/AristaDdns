import os
import sys

from dnscrypt_parser import DNSCryptParser
from doh_parser import DOHParser
from normalizer import Normalizer
from deduplicator import Deduplicator
from classifier import Classifier
from generator import Generator


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")


def main():
    try:
        os.makedirs(DATA_DIR, exist_ok=True)

        dnscrypt_data = DNSCryptParser.fetch()
        doh_data = DOHParser.fetch()

        print(f"DNSCrypt entries: {len(dnscrypt_data)}")
        print(f"DoH entries: {len(doh_data)}")

        all_dns = dnscrypt_data + doh_data

        if not all_dns:
            print("No DNS data collected")
            sys.exit(1)

        normalized = Normalizer.normalize(all_dns)
        validated = Normalizer.validate(normalized)
        deduplicated = Deduplicator.deduplicate(validated)
        classified = Classifier.classify(deduplicated)

        print(f"Normalized entries: {len(normalized)}")
        print(f"Validated entries: {len(validated)}")
        print(f"Unique entries: {len(deduplicated)}")
        print(f"Classified entries: {len(classified)}")

        generator = Generator(classified)
        generator.save()

        print("DNS collection completed successfully")
        sys.exit(0)

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
