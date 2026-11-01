import yaml


def load_config(file_path) -> dict:
    with open(file_path, 'r', encoding='utf-8') as file:
        config = yaml.safe_load(file)
        if config is None:
            raise ValueError(f"Configuration file '{file_path}' is empty")
        if not isinstance(config, dict):
            raise ValueError("Configuration must be a YAML mapping")
    return config