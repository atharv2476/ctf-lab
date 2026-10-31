import sys, json, base64
def e(o):
    return base64.urlsafe_b64encode(json.dumps(o, separators=(",", ":")).encode()).rstrip(b"=").decode()
h = json.loads(sys.argv[1]); p = json.loads(sys.argv[2])
print(e(h) + "." + e(p) + ".")
