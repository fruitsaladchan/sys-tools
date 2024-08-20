import sys
import time

def slowprint(s, delay=1./200):
    """Prints a string with a slow typing effect."""
    for c in s + '\n':
        sys.stdout.write(c)
        sys.stdout.flush()
        time.sleep(delay)

def slowinput(prompt, delay=1./200):
    """Displays a prompt with a slow typing effect and captures user input."""
    slowprint(prompt, delay)
    return input()

# Usage example
domain = slowinput("Enter a domain: ")
