# NZ Vaccine Pass Verify

Python script to validate the NZ Covid-19 vaccine pass, specified [here](https://github.com/minhealthnz/nzcovidpass-spec).

Scan the QR code, and pass the payload to the script. It will then decode the payload & validate the pass. If valid, it
will print out the details of the pass holder. If invalid, it will throw an exception.

## Installation

```
pip3 install -r requirements.txt
```

## Usage

```
python3 verify.py <qr_payload>
```
