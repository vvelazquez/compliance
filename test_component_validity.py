import logging
from glob import iglob
from pykwalify.core import Core
from pykwalify.errors import SchemaError
import yaml

logging.basicConfig()

def get_schema(version):
    """ Load contents of schema file """
    path = 'v{}.yaml'.format(version)
    contents = open(path)
    return yaml.load(contents)

def create_validator(source_data):
    """ Generate validator from PyKwalify """
    version = source_data.get('schema_version', '3.1.0')
    schema = get_schema(version)
    validator = Core(source_data={}, schema_data=schema)
    validator.source = source_data
    return validator

def test_component_validity():
    """ Test component validity against the OpenControl schema """
    for component_file in iglob('*/component.yaml'):
        print(component_file)
        source_data = yaml.load(open(component_file))
        validator = create_validator(source_data)
        try:
            validator.validate(raise_exception=True)
        except SchemaError:
            assert False, "Error found in: {0}".format(component_file)
