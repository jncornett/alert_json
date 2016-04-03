# Alert JSON

A JSON alert plugin for [Snort 3](https://github.com/snortadmin/snort3).

# Installation

In short:

    git clone https://github.com/jncornett/alert_json.git
    mkdir build && cd build
    cmake ..
    make

## Dependencies

 - Snort 3: https://github.com/snortadmin/snort3
 - RapidJSON: http://rapidjson.org/

## Notes

 - AlertJSON uses PkgConfig to locate its dependencies, so make sure that you set `PKG_CONFIG_PATH` appropriately

## Usage

To output alerts to a file:

    $ snort --plugin-path $alert_json_path -A alert_json --lua "{ path='output.json' }" $snort_args

Output alerts in compact form, to STDERR:

    $ snort --plugin-path $alert_json_path -A alert_json --lua "{ path='stderr', pretty = false }" $snort_args
