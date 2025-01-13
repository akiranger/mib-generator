import pandas as pd
from collections import defaultdict
import yaml
import os


def load_config(config_file):
    config_path = os.path.join(os.path.dirname(__file__), "..", config_file)
    with open(config_path, "r") as file:
        return yaml.safe_load(file)


def generate_asn1_definitions(csv_file, config):
    try:
        df = pd.read_csv(csv_file)
    except FileNotFoundError:
        return "Error: CSV file not found. Please provide a valid CSV file."
    except pd.errors.ParserError as e:
        return f"Error parsing CSV file: {e}"

    definitions = generate_definitions(config["module_name"])
    module_identity = generate_module_identity(config)
    imports, objects = generate_objects(df, config["module_name"], config["base_oid"])

    asn1_definitions = "\n\n".join(
        [definitions, imports, module_identity, objects, "END"]
    )
    return asn1_definitions


def generate_definitions(module_name):
    return f"{module_name} DEFINITIONS ::= BEGIN"


def generate_module_identity(config):
    return f"""{config['module_name']} MODULE-IDENTITY
    LAST-UPDATED "{config['last_updated']}"
    ORGANIZATION "{config['organization']}"
    CONTACT-INFO "{config['contact_info']}"
    DESCRIPTION "{config['description']}"
    REVISION "{config['last_updated']}"
    DESCRIPTION "Initial version"
    ::= {{ {config['base_oid']} }}"""


def generate_objects(df, module_name, base_oid):
    imports = defaultdict(set)
    objects = []
    enums = {}

    for _, row in df.iterrows():
        oid = row.get("OID", "").strip()
        name = row.get("Name", "").strip()
        syntax = row.get("Type", "").strip()
        description = row.get("Description", "").strip() or "No description provided."
        access = row.get("Access", "not-accessible").strip()
        status = row.get("Status", "current").strip()
        enum_values = str(row.get("EnumValues", "")).strip()

        # Debugging output
        print(f"OID: {oid}")
        print(f"Name: {name}")
        print(f"Syntax: {syntax}")
        print(f"Description: {description}")
        print(f"Access: {access}")
        print(f"Status: {status}")
        print(f"EnumValues: {enum_values}")

        if enum_values and enum_values.lower() != "nan":
            enum_name = f"{name}Val"
            enums[enum_name] = enum_values
            syntax = enum_name

        add_to_imports(imports, row.get("Type", "").strip())

        objects.append(
            generate_object(
                name, syntax, access, status, description, module_name, oid, base_oid
            )
        )

    imports_section = generate_imports(imports)
    enums_section = generate_enums(enums)
    objects_section = "\n\n".join(objects)

    return imports_section, f"{enums_section}\n\n{objects_section}"


def add_to_imports(imports, syntax):
    standard_types = {
        "Integer32": "SNMPv2-SMI",
        "Gauge32": "SNMPv2-SMI",
        "Counter64": "SNMPv2-SMI",
        "TimeTicks": "SNMPv2-SMI",
        "IpAddress": "SNMPv2-SMI",
        "DisplayString": "SNMPv2-TC",
        "OCTET STRING": "SNMPv2-SMI",
        "OBJECT IDENTIFIER": "SNMPv2-SMI",
    }
    if syntax in standard_types:
        imports[standard_types[syntax]].add(syntax)


def generate_imports(imports):
    if not imports:
        return ""

    imports_list = []
    for module, symbols in imports.items():
        imports_list.append(f"    {', '.join(sorted(symbols))}\n        FROM {module}")

    return "IMPORTS\n" + ";\n".join(imports_list) + ";"


def generate_enums(enums):
    enum_definitions = []
    for enum_name, enum_values in enums.items():
        values = enum_values.split(",")
        enum_def = f"{enum_name} ::= INTEGER {{\n"
        enum_def += ",\n".join(f"    {value.strip()}" for value in values)
        enum_def += "\n}"
        enum_definitions.append(enum_def)
    return "\n\n".join(enum_definitions)


def generate_object(
    name, syntax, access, status, description, module_name, oid, base_oid
):
    oid_parts = oid.split('.')
    base_oid_parts = base_oid.split('.')
    relative_oid = oid_parts[len(base_oid_parts):]
    relative_oid_str = ' '.join(relative_oid)
    return f"""{name} OBJECT-TYPE
    SYNTAX      {syntax}
    MAX-ACCESS  {access}
    STATUS      {status}
    DESCRIPTION
        "{description}"
    ::= {{ {module_name} {relative_oid_str} }}"""


def main():
    config = load_config("config.yaml")
    csv_path = os.path.join(os.path.dirname(__file__), "..", config["csv_file"])
    asn1_output = generate_asn1_definitions(csv_path, config)

    output_path = os.path.join(os.path.dirname(__file__), "..", config["output_file"])
    with open(output_path, "w") as f:
        f.write(asn1_output)
    print(f"MIB definition has been written to {config['output_file']}")


if __name__ == "__main__":
    main()
