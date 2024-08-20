import sys
import time

def slowprint(s, delay=1./200, newline=True):
    """Prints a string with a slow typing effect. Optionally appends a newline."""
    for c in s:
        sys.stdout.write(c)
        sys.stdout.flush()
        time.sleep(delay)
    if newline:
        sys.stdout.write('\n')
        sys.stdout.flush()

def slowinput(prompt, delay=1./200):
    """Displays a prompt with a slow typing effect without a newline, and captures user input."""
    slowprint(prompt, delay, newline=False)  # Print the prompt without newline
    return input()  # Capture user input

# Usage example
domain = slowinput("Enter a domain: ")
print(f"You entered: {domain}")
