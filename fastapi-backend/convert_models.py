from keras.models import load_model
import os

# Try to load and resave models with compatible format using standalone Keras

base_dir = os.path.dirname(__file__)

for name in ['char_cnn', 'cnn_gru']:
    try:
        model_path = os.path.join(base_dir, 'models', name, 'model.keras')
        model = load_model(model_path)
        output_path = os.path.join(base_dir, 'models', name, 'model_converted.keras')
        model.save(output_path)
        print(f"{name} model converted to {output_path}")
    except Exception as e:
        print(f"Failed to convert {name}: {e}")