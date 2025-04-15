#!/usr/bin/env python3
"""
POST Data Handler module for the Web Security Fuzzer
"""

import json
import urllib.parse


class PostDataHandler:
    def __init__(self):
        pass

    def parse_post_data(self, post_data, content_type=None):
        """
        Parse POST data and extract parameters based on content type

        Args:
            post_data (str): Raw POST data
            content_type (str, optional): Content-Type header. Defaults to None.

        Returns:
            dict: Dictionary containing parsed parameters
        """
        result = {
            'original_data': post_data,
            'parameters': {}
        }

        try:
            # Handle JSON data
            if content_type and 'application/json' in content_type.lower():
                json_data = json.loads(post_data)
                # Flatten JSON to handle nested structures
                self._flatten_json(json_data, result['parameters'])

            # Handle form data (application/x-www-form-urlencoded)
            elif not content_type or 'application/x-www-form-urlencoded' in content_type.lower():
                query_params = urllib.parse.parse_qs(post_data)
                # Convert values from lists to single values
                for param, values in query_params.items():
                    result['parameters'][param] = values[0] if values else ''

            # Handle multipart/form-data (basic support)
            elif content_type and 'multipart/form-data' in content_type.lower():
                # Basic parsing - in a real scenario we'd use proper multipart parsing
                # but for our testing purposes this simplified approach is sufficient
                if '--' in post_data:
                    parts = post_data.split('--')
                    for part in parts:
                        if 'name="' in part:
                            name_start = part.find('name="') + 6
                            name_end = part.find('"', name_start)
                            if name_start > 6 and name_end > name_start:
                                param_name = part[name_start:name_end]

                                # Find the value (after the double newline)
                                value_start = part.find('\r\n\r\n', name_end)
                                if value_start > 0:
                                    value_start += 4  # Skip the double newline
                                    value = part[value_start:].strip()
                                    result['parameters'][param_name] = value

            # If we can't determine content type but have data, try to parse as form data
            elif post_data:
                # Try to parse as JSON first
                try:
                    json_data = json.loads(post_data)
                    self._flatten_json(json_data, result['parameters'])
                except ValueError:
                    # If not valid JSON, try as form data
                    query_params = urllib.parse.parse_qs(post_data)
                    for param, values in query_params.items():
                        result['parameters'][param] = values[0] if values else ''

        except Exception as e:
            print(f"[!] Error parsing POST data: {e}")

        return result

    def _flatten_json(self, json_obj, result, prefix=''):
        """
        Recursively flatten JSON object into a single-level dictionary

        Args:
            json_obj (dict/list): JSON object to flatten
            result (dict): Result dictionary to populate
            prefix (str): Prefix for nested keys
        """
        if isinstance(json_obj, dict):
            for key, value in json_obj.items():
                new_key = f"{prefix}.{key}" if prefix else key
                if isinstance(value, (dict, list)):
                    self._flatten_json(value, result, new_key)
                else:
                    result[new_key] = value
        elif isinstance(json_obj, list):
            for i, value in enumerate(json_obj):
                new_key = f"{prefix}[{i}]"
                if isinstance(value, (dict, list)):
                    self._flatten_json(value, result, new_key)
                else:
                    result[new_key] = value

    def inject_payload_to_post_data(self, post_data, param_name, payload, content_type=None):
        """
        Inject a payload into POST data based on the content type

        Args:
            post_data (str): Original POST data
            param_name (str): Parameter to inject payload into
            payload (str): The payload
            content_type (str, optional): Content-Type header. Defaults to None.

        Returns:
            str: POST data with injected payload
        """
        try:
            # Handle JSON data
            if content_type and 'application/json' in content_type.lower():
                try:
                    # Parse the JSON
                    json_data = json.loads(post_data)

                    # Inject payload (handling nested parameters with dot notation)
                    if '.' in param_name:
                        parts = param_name.split('.')
                        current = json_data

                        # Navigate to the nested location
                        for i, part in enumerate(parts):
                            # Handle array index notation [n]
                            if '[' in part and ']' in part:
                                array_name = part.split('[')[0]
                                index = int(part.split('[')[1].split(']')[0])

                                if i == len(parts) - 1:
                                    current[array_name][index] = payload
                                else:
                                    current = current[array_name][index]
                            else:
                                if i == len(parts) - 1:
                                    current[part] = payload
                                else:
                                    if part not in current:
                                        current[part] = {}
                                    current = current[part]
                    else:
                        # Handle array index notation [n]
                        if '[' in param_name and ']' in param_name:
                            array_name = param_name.split('[')[0]
                            index = int(param_name.split('[')[1].split(']')[0])
                            json_data[array_name][index] = payload
                        else:
                            json_data[param_name] = payload

                    # Convert back to string
                    return json.dumps(json_data)
                except Exception as e:
                    print(f"[!] Error injecting payload to JSON: {e}")
                    return post_data

            # Handle form data
            elif not content_type or 'application/x-www-form-urlencoded' in content_type.lower():
                query_params = urllib.parse.parse_qs(post_data)

                # Convert values from lists to single values
                params = {k: v[0] if v else '' for k,
                          v in query_params.items()}

                # Inject payload
                params[param_name] = payload

                # Encode back to string
                return urllib.parse.urlencode(params, safe="*()'-=<>\"{}[];:,./?")

            # For other content types, simple string replacement if parameter exists
            else:
                if param_name in post_data:
                    # Very basic replacement - in a real scenario, more sophisticated parsing would be needed
                    parts = post_data.split(param_name + '=')
                    if len(parts) > 1:
                        # Find the end of the parameter value
                        value_end = parts[1].find('&')
                        if value_end == -1:
                            value_end = len(parts[1])

                        # Replace the value
                        return parts[0] + param_name + '=' + urllib.parse.quote(payload, safe="*()'-=<>\"{}[];:,./?") + parts[1][value_end:]

                return post_data

        except Exception as e:
            print(f"[!] Error injecting payload to POST data: {e}")
            return post_data
