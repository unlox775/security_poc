import inspect
import pprint
import sys
import os
from typing import Any


def bug(*args) -> None:
    """
    Debug function that prints the calling file, line number, and pretty-prints the object.
    
    Args:
        *args: Either (obj) or (label, obj)
            - If one argument: obj is the object to debug print with "BUG" as label
            - If two arguments: first is label, second is object to debug print
        
    Example:
        bug("Hello world")  # Prints: [file.py:123] BUG: Hello world
        bug("COOKIES", {"key": "value"})  # Prints: [file.py:123] COOKIES: {'key': 'value'}
    """
    # Get the caller's frame info
    caller_frame = inspect.currentframe().f_back
    if caller_frame:
        filename = caller_frame.f_code.co_filename
        line_number = caller_frame.f_lineno
        
        # Extract just the filename without the full path
        filename = filename.split('/')[-1]
        
        # Determine label and object based on number of arguments
        if len(args) == 1:
            obj = args[0]
            # Try to extract the source code for a better label
            try:
                # Get the actual source line
                with open(caller_frame.f_code.co_filename, 'r') as f:
                    lines = f.readlines()
                    if line_number <= len(lines):
                        source_line = lines[line_number - 1].strip()
                        
                        # Try to extract just the argument part
                        # Look for bug( and extract what's inside
                        if 'bug(' in source_line:
                            # Find the opening and closing parentheses
                            start = source_line.find('bug(') + 4
                            paren_count = 0
                            end = start
                            
                            for i, char in enumerate(source_line[start:], start):
                                if char == '(':
                                    paren_count += 1
                                elif char == ')':
                                    if paren_count == 0:
                                        end = i
                                        break
                                    paren_count -= 1
                                elif char == ',' and paren_count == 0:
                                    # Stop at first comma if no nested parentheses
                                    end = i
                                    break
                            
                            # Extract the argument and clean it up
                            arg_part = source_line[start:end].strip()
                            # Remove common prefixes/suffixes and clean up
                            arg_part = arg_part.replace('self.', '').replace('(', '').replace(')', '')
                            label = f"BUG \"{arg_part}\" "
                        else:
                            # Fallback: use the whole line cleaned up
                            clean_line = source_line.replace('bug(', '').replace(')', '').strip()
                            label = f"BUG \"{clean_line}\" "
                    else:
                        label = "BUG"
            except (FileNotFoundError, IndexError, UnicodeDecodeError):
                label = "BUG"
        elif len(args) == 2:
            label = args[0]
            obj = args[1]
        else:
            raise ValueError("bug() takes 1 or 2 arguments")
        
        # Print file and line info with label
        print(f"\n{label}[{filename}:{line_number}]:\n", end=" ")
    
    # Pretty print the object
    if isinstance(obj, (dict, list, tuple, set)):
        pprint.pprint(obj, width=80, depth=None)
    else:
        print(obj)
