import sys, json, os
import torch

model_path, input_path = sys.argv[1], sys.argv[2]

with open(input_path, 'rb') as f:
    raw = f.read()

try:
    data = json.loads(raw)
    if isinstance(data, list):
        values, shape = data, [1, len(data)]
    elif isinstance(data, dict):
        vals = data.get('input') or data.get('data') or data.get('values', [])
        shape = data.get('shape', [1, max(len(vals), 1)])
        values = vals
    else:
        values, shape = [float(data)], [1, 1]
except Exception:
    values, shape = [0.0], [1, 1]

model = torch.jit.load(model_path, map_location='cpu')
model.eval()
with torch.no_grad():
    t = torch.tensor(values, dtype=torch.float32).reshape(shape)
    out = model(t)
    out_list = out.flatten().tolist()
    out_shape = list(out.shape)

print(json.dumps({"type": "f32", "shape": out_shape, "values": out_list}), end='')
