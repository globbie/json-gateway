#!/usr/bin/env python3

import logging
import json
import enum


class KnowdyService(enum.Enum):
    delivery = {'address': 'ipc:///var/lib/knowdy/delivery/inbox'}
    read = {'address': 'tcp://127.0.0.1:6900'}
    write = {'address': 'tcp://127.0.0.1:6908'}


class Action(enum.Enum):
    new = 'new'
    get = 'get'
    select = 'select'


class Translation:
    def __init__(self, input_: str):
        self.gsl_result = None
        self.service = None
        self.async = False

        self.json_parse(input_)

    def json_parse_unit(self, unit_key: str, input_dict: dict) -> str:
        logging.debug('parsing \'%s\' unit' % unit_key)

        output_dict = []
        action = Action.get

        logging.debug(input_dict)

        if 'retrieve' == unit_key:
            self.service = KnowdyService.delivery

            if 'tid' in input_dict:
                pass
            else:
                raise ValueError

        if 'async' in input_dict:
            if input_dict['async']:
                self.async = True

        if 'action' in input_dict:  # reserved keyword for unit type
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

        logging.debug('action \'%s\'' % action.value)

        if action == Action.new:
            output_dict.append('(')
        else:
            output_dict.append('{')

        output_dict.append(unit_key)

        if 'n' in input_dict:  # reserved keyword for name
            value = input_dict['n']

            if type(value) != str:
                raise TypeError

            logging.debug('name: \'%s\'' % value)
            output_dict.append(' %s' % value)

        for key, value in input_dict.items():
            if key == 'action':
                continue
            if key == 'n':
                continue
            if key == 'async':
                continue

            if type(value) == dict:
                output_dict.append(self.json_parse_unit(key, value))
            elif type(value) == str:
                logging.debug('appending %s : %s' % (key, value))
                output_dict.append('{%s %s}' % (key, value))

        if action == Action.new:
            output_dict.append(')')
        else:
            output_dict.append('}')

        logging.debug(output_dict)
        return "".join(output_dict)

    def json_parse(self, input_: str):
        input_dict = json.loads(input_)
        output_list = []

        for key, value in input_dict.items():
            output_list.append(self.json_parse_unit(key, input_dict[key]))

        self.gsl_result = "".join(output_list)
        return self


if __name__ == '__main__':
    logging.basicConfig(level=logging.ERROR)

    input_array = []
    try:
        while True:
            input_array.append(input())
    except EOFError:
        pass

    input_file = "\n".join(input_array)
    translation = Translation(input_file)

    print(translation.gsl_result)

