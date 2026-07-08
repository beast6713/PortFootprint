"""
PortParser utility parsing ranges, lists, and values into verified unique ports.
"""


from portfootprint.core.constants import MAX_PORT, MIN_PORT
from portfootprint.core.exceptions import InvalidPortError


class PortParser:
    """
    Parses CLI port input strings into a sorted, unique list of integers.
    Supports single values, comma-separated lists, and hyphenated ranges.
    """
    @staticmethod
    def _validate_port_range(port: int) -> None:
        if not (MIN_PORT <= port <= MAX_PORT):
            raise InvalidPortError(
                f"Port number {port} is out of bounds. Valid ranges: {MIN_PORT}-{MAX_PORT}."
            )

    def parse(self, port_str: str) -> list[int]:
        """
        Parses port strings (e.g., '80', '22,80,443', '20-100', '22,80-90,443')
        into a sorted list of unique valid ports.
        Raises InvalidPortError on failure.
        """
        if not port_str or not port_str.strip():
            raise InvalidPortError("Ports configuration parameter cannot be empty.")

        # Clean spaces and split by commas
        cleaned_str = port_str.replace(" ", "")
        parts = cleaned_str.split(",")
        ports: set[int] = set()

        for part in parts:
            if not part:
                continue

            # Check if part represents a range (e.g., 20-100)
            if "-" in part:
                range_parts = part.split("-")
                if len(range_parts) != 2:
                    raise InvalidPortError(f"Malformed port range syntax: '{part}'.")

                start_str, end_str = range_parts
                try:
                    start_port = int(start_str)
                    end_port = int(end_str)
                except ValueError as e:
                    raise InvalidPortError(
                        f"Non-numeric values in port range: '{part}'."
                    ) from e

                if start_port > end_port:
                    raise InvalidPortError(
                        f"Port range start ({start_port}) cannot be greater than end ({end_port})."
                    )

                self._validate_port_range(start_port)
                self._validate_port_range(end_port)

                # Add entire range
                for p in range(start_port, end_port + 1):
                    ports.add(p)

            else:
                # Parse as single integer
                try:
                    port = int(part)
                except ValueError as e:
                    raise InvalidPortError(f"Invalid non-integer port value: '{part}'.") from e

                self._validate_port_range(port)
                ports.add(port)

        if not ports:
            raise InvalidPortError(f"No valid ports parsed from raw string: '{port_str}'.")

        return sorted(ports)
