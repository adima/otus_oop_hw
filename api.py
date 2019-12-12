#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import json
import datetime
import logging
import hashlib
import uuid
from optparse import OptionParser
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from scoring import get_interests, get_score

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}
NULL_VALUES = [None, '']

def validator_string_type(value):
    """
    Функция. которая валидирует. что значение относится к строковому типу
    :param value: значение
    :return:
    """
    if value in NULL_VALUES:
        return
    if type(value) not in [str, unicode]:
        raise ValueError("Type of value is not string")

def validator_clients_list(value):
    if not value:
        raise ValueError("List is empty on None")

class BaseField(object):
    """
    Базовый класс для полей
    """

    null_values = NULL_VALUES
    validators = []
    val = None

    def __init__(self, required=False, nullable=False):
        self.required = required
        self.nullable = nullable

    def isnull(self, value):
        if value in self.null_values:
            return True
        else:
            return False

    def validate(self, value):
         if self.isnull(value) and (self.required or not self.nullable):
            raise ValueError("Required field is empty")

    def run_validators(self, value):
        errors = []
        for v in self.validators:
            try:
                v(value)
            except ValueError as e:
                errors.append(str(e))
        if errors:
            raise ValueError('\n'.join(errors))

    def clean(self, value):
        self.val = None
        self.validate(value)
        self.run_validators(value)
        self.val = value
        return value

    def isnull_assigned(self):
        return self.isnull(self.val)

    # def __get__(self):
    #     return self.val


class CharField(BaseField):
    """
    Класс поля со строкой
    """
    validators = BaseField.validators + [validator_string_type]


class ArgumentsField(BaseField):
    pass


class EmailField(CharField):
    pass


class PhoneField(BaseField):
    pass


class DateField(BaseField):
    pass


class BirthDayField(BaseField):
    pass


class GenderField(BaseField):
    pass


class ClientIDsField(BaseField):
    validators = BaseField.validators + [validator_clients_list]



class RequestMeta(type):
    def __new__(mcs, name, bases, attrs):
        def get_method_score(self):
            store = {}
            if self.scoring_check():
                return OK, self.scoring_func(**self.arguments)
            else:
                return None, INVALID_REQUEST

        fields = []
        for key, value in attrs.items():
            if isinstance(value, BaseField):
                fields.append((key, value))
                attrs.pop(key)

        attrs['fields'] = dict(fields)
        if 'scoring_check' and 'scoring_func' in attrs:
            attrs['get_method_score'] = get_method_score
        new_class = super(RequestMeta, mcs).__new__(mcs, name, bases, attrs)
        return new_class


# class MethodRequestMeta(RequestMeta):
#     def __init__(cls, name, bases, attrs, **kwargs):
#         if 'method' in attrs['args']:
#             setattr(cls, attrs['args']['method'], attrs['args']['method'])
        # super(RequestMeta, cls).__init__(name, bases, attrs)
#

class RequestBase(object):
    fields = {}
    clean_args = {}

    def __init__(self, args):
        if args is None:
            args = {}
        self._raw_args = args
        self.assign_fields()

    def pass_args(self, args):
        self._raw_args = args

    def assign_fields(self):
        arguments = {}
        self.fields_errs = []
        for field_name, field_inst in self.fields.items():
            try:
                arguments[field_name] = field_inst.clean(self._raw_args.get(field_name, None ))
            except ValueError as e:
                self.fields_errs.append(field_name + ': ' + str(e))
        # if errs:
        #     raise ValueError('\n'.join(errs))
        self.clean_args = arguments

    @property
    def arguments(self):
        return self.clean_args

    @arguments.setter
    def arguments(self, args):
        self._raw_args = args
        self.assign_fields()



class ClientsInterestsRequest(RequestBase):
    __metaclass__ = RequestMeta
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)
    scoring_func = get_interests
    def scoring_check(self):
        return True




class OnlineScoreRequest(RequestBase):
    __metaclass__ = RequestMeta
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)
    scoring_func = get_score

    def scoring_check(self):
        fields = self.fields
        return (not fields['phone'].isnull_assigned() and not fields['email'].isnull_assigned()) or \
            (not fields['first_name'].isnull_assigned() and not fields['last_name'].isnull_assigned()) or \
                (not fields['gender'].isnull_assigned() and not fields['birthday'].isnull_assigned())


class MethodRequest(RequestBase):
    __metaclass__ = RequestMeta
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    method_map = {'online_score': OnlineScoreRequest,
                  'clients_interests': ClientsInterestsRequest}

    def __init__(self, args):
        super(MethodRequest, self).__init__(args)
        # method_value = self.method.clean(args['method'])
        # args_value = self.arguments.clean(args['arguments'])
        method = self.fields['method'].val
        arguments = self.fields['arguments'].val
        self.method_err = None
        try:
            self.method_inst = self.method_map[method](arguments)
        except ValueError as e:
            self.method_err = str(e)
        except KeyError:
            pass

    def check_auth(self):
        if self.is_admin:
            digest = hashlib.sha512(datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).hexdigest()
        else:
            digest = hashlib.sha512(self.fields['account'].val + self.fields['login'].val + SALT).hexdigest()
        if digest == self.fields['token'].val:
            return True
        return False

    @property
    def is_admin(self):
        return self.fields['login'].val == ADMIN_LOGIN

    def get_response(self):
        if not self.check_auth():
            return 'Wrong Credentials', FORBIDDEN
        elif self.fields_errs:
            return '\n'.join(self.fields_errs), INVALID_REQUEST
        elif self.method_err:
            return self.method_err, INVALID_REQUEST
        else:
            return self.method_inst.get_method_score()





def check_request(request):
    if 'body' not in request:
        return ERRORS[INVALID_REQUEST], INVALID_REQUEST

    elif 'login' not in request['body']:
        return ERRORS[INVALID_REQUEST], INVALID_REQUEST
    return None, None


def method_handler(request, ctx, store):
    bad_reason, bad_code = check_request(request)
    if bad_reason:
        return bad_reason, bad_code

    # elif not check_auth(request_body):
    #     return ERRORS[FORBIDDEN], FORBIDDEN
    # elif request_body.method is None:
    #     return ERRORS[INVALID_REQUEST], INVALID_REQUEST
    # else:
    #     return None, None



    method_request = MethodRequest(request['body'])
    return method_request.get_response()
    # pass



    # response, code = None, None
    # return response, code


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
                except Exception, e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r))
        return


if __name__ == "__main__":
    # op = OptionParser()
    # op.add_option("-p", "--port", action="store", type=int, default=8080)
    # op.add_option("-l", "--log", action="store", default=None)
    # (opts, args) = op.parse_args()
    # logging.basicConfig(filename=opts.log, level=logging.INFO,
    #                     format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    # server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    # logging.info("Starting server at %s" % opts.port)
    # try:
    #     server.serve_forever()
    # except KeyboardInterrupt:
    #     pass
    # server.server_close()

    # intests = ClientsInterestsRequest({'client_ids': '1', 'date': '12.12.2018'})
    # print intests.arguments
    # req = MethodRequest(dict(method='hui'))
    # print 'whoa python 2'

    context = {}
    headers = {}
    settings = {}
    # arguments = {'email': 'stupnikov@otus.ru', 'phone': '79175002040'}
    arguments = {"client_ids": [1, 2, 3], "date": datetime.datetime.today().strftime("%d.%m.%Y")}
    # arguments = {'phone': '79175002040', 'birthday': '01.01.1890', 'email': 'stupnikov@otus.ru', 'gender': 1}
    request = {"account": "horns&hoofs", "login": "h&f", "method": "online_score", "arguments": arguments}
    # request = {"account": "horns&hoofs", "login": "admin", "method": "online_score", "arguments": arguments}
    request["token"] = hashlib.sha512(datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).hexdigest()
    # msg = request.get("account", "") + request.get("login", "") + SALT
    # request["token"] = hashlib.sha512(msg).hexdigest()
    # request = {}
    response, code = method_handler({"body": request, "headers": headers}, context, settings)
    print(response, code)
