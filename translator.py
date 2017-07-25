#!/usr/bin/env python3

import inspect
import logging
import json
import enum


def debug(msg):
    frame, filename, line_number, function_name, lines, index = inspect.getouterframes(inspect.currentframe())[1]

    line = lines[0]
    indentation_level = line.find(line.lstrip())
    logging.debug('{i}{m}'.format(i=' '*indentation_level, m=msg))


class Action(enum.Enum):
    new = 'new'
    get = 'get'
    select = 'select'


def json_parse_unit(unit_key: str, input_dict: dict) -> str:
    debug('parsing \'%s\' unit' % unit_key)

    output_dict = []
    action = Action.get

    debug(input_dict)

    if 'action' in input_dict:
        value = input_dict['action']

        if type(value) != str:
            raise TypeError

        if value == Action.new.value:
            action = Action.new
        elif value == Action.select.value:
            action = Action.select
        elif value == Action.get.value:
            action = Action.get
        else:
            raise ValueError

    debug('action \'%s\'' % action.value)

    if action == Action.new:
        output_dict.append('(')
    else:
        output_dict.append('{')

    output_dict.append(unit_key)

    if 'n' in input_dict:  # reserved keyword
        value = input_dict['n']

        if type(value) != str:
            raise TypeError

        debug('name: \'%s\'' % value)
        output_dict.append(' %s' % value)

    for key, value in input_dict.items():
        if key == 'action':
            continue
        if key == 'n':
            continue

        if type(value) == dict:
            output_dict.append(json_parse_unit(key, value))
        elif type(value) == str:
            debug('appending %s : %s' % (key, value))
            output_dict.append('{%s %s}' % (key, value))

    if action == Action.new:
        output_dict.append(')')
    else:
        output_dict.append('}')

    debug(output_dict)
    return "".join(output_dict)


def json_to_gsl(input_str: str) -> str:
    input_dict = json.loads(input_str)
    output_list = []

    for key in input_dict:
        output_list.append(json_parse_unit(key, input_dict[key]))

    return "".join(output_list)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)

    input_array = []
    try:
        while True:
            input_array.append(input())
    except EOFError:
        pass

    input_file = "\n".join(input_array)
    print(json_to_gsl(input_file))

