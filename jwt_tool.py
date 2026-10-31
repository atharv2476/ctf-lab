import sys, json, base64
def d(s):
    return json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
t = sys.argv[1].split(".")
print("HEADER :", json.dumps(d(t[0])))
print("PAYLOAD:", json.dumps(d(t[1])))
