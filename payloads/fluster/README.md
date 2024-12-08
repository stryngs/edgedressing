## What
fluster is a payload meant to be as easy as 1, 2, 3.  The aim of which being to hone a cookie capturing concept.

Radiotap anyone?

#### 1.py
- Spins up X number of webservers
- Creates Y number of cookies per port
- Creates cookies.ckl for `2.py`
- Creates successful_ports.txt for `2.py` and `3.py`

#### 2.py
- Grabs cookies
- Saves pcaps

#### 3.py
- Uses successful_ports.txt as stdin for sending naked GET
- Notates received cookies
- Sends same GET 2nd time with prior received cookies
- Optionally includes cookies from cookies.ckl in the first send

## How
ChatGPT and live testing feedback to the prompt.
