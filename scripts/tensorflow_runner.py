import sys, json, os
import numpy as np
import tensorflow as tf

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

arr = np.array(values, dtype=np.float32).reshape(shape)

if os.path.isdir(model_path):
    model = tf.saved_model.load(model_path)
    infer = model.signatures.get('serving_default')
    if infer:
        key = list(infer.structured_input_signature[1].keys())[0]
        result = infer(**{key: tf.constant(arr)})
        out = list(result.values())[0].numpy()
    else:
        out = model(arr).numpy()
else:
    model = tf.keras.models.load_model(model_path)
    out = model.predict(arr, verbose=0)

out_list = out.flatten().tolist()
out_shape = list(out.shape)
print(json.dumps({"type": "f32", "shape": out_shape, "values": out_list}), end='')
