#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import json
import datetime
import logging
import hashlib
import uuid
import numbers
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
    """
    Валидация списка клиентов
    """
    if type(value) is not list:
        raise ValueError("Value is not a list")
    if not value:
        raise ValueError("List is empty on None")


def validator_client_ids_isnum(values):
    """
    Валидация ID клиента на числовой тип
    """
    if not all([isinstance(val, numbers.Number) for val in values]):
        raise ValueError("Client ids should be numeric")


def validator_date(value):
    """
    Валидация даты
    """
    if value:
        try:
            d = datetime.datetime.strptime(value, '%d.%m.%Y')
        except ValueError:
            raise ValueError("Date is not in correct format")


def validator_birthday(value):
    """
    Валидация дня рождения
    """
    if value:
        d = datetime.datetime.strptime(value, '%d.%m.%Y')
        if (datetime.datetime.now() - d).days / 365.25 > 70:
            raise ValueError("Birthday should be less than 70 years from now")


def validator_phone(value):
    """
    Валидация телефона
    """
    if value:
        values_s = str(value)
        if not values_s.isdigit():
            raise ValueError("Phone does not consist of digits")
        elif not values_s.startswith('7'):
            raise ValueError("Phone does not consist of digits")
        elif len(values_s) != 11:
            raise ValueError("Phone doesn't have length 11 digits")


def validator_email(value):
    """
    Валидация email
    """
    if value:
        if '@' not in value:
            raise ValueError("Email does not contain @ sign")


def validator_gender(value):
    """
    Валидация пола
    """
    if value:
        if value not in [0, 1, 2]:
            raise ValueError("Gender should be a number 0, 1 or 2")


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
                continue
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


class CharField(BaseField):
    """
    Класс поля со строкой
    """
    validators = BaseField.validators + [validator_string_type]


class ArgumentsField(BaseField):
    pass


class EmailField(CharField):
    validators = CharField.validators + [validator_email]


class PhoneField(BaseField):
    validators = BaseField.validators + [validator_phone]


class DateField(BaseField):
    validators = BaseField.validators + [validator_date]


class BirthDayField(DateField):
    validators = DateField.validators + [validator_birthday]


class GenderField(BaseField):
    validators = BaseField.validators + [validator_gender]


class ClientIDsField(BaseField):
    validators = BaseField.validators + [validator_clients_list, validator_client_ids_isnum]


class RequestMeta(type):
    """
    Метакласс для создания объектов типа Request. Может быть использован как для ScoreRequest, InterestsRequests,
    так для MethodRequests
    """
    def __new__(mcs, name, bases, attrs):
        def get_method_score(self, ctx, store):
            """
            Если класс имеет атрибуты scoring check и scoring func, в его словарь также добавляется
            функция get_method_score
            """
            if self.scoring_check():
                req_resp = self.scoring_func(store, ctx, **self.arguments)
                return req_resp, OK
            else:
                return 'Conditions are not satisfied', INVALID_REQUEST

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


class RequestBase(object):
    fields = {}
    clean_args = {}
    fields_errs = []

    def __init__(self, argmnts):
        if argmnts is None:
            argmnts = {}
        self._raw_args = argmnts
        self.assign_fields()

    def pass_args(self, argmnts):
        self._raw_args = argmnts

    def assign_fields(self):
        arguments = {}
        self.fields_errs = []
        for field_name, field_inst in self.fields.items():
            try:
                arguments[field_name] = field_inst.clean(self._raw_args.get(field_name, None ))
            except ValueError as e:
                arguments[field_name] = None
                self.fields_errs.append(field_name + ': ' + str(e))
        self.clean_args = arguments

    @property
    def arguments(self):
        return self.clean_args

    @arguments.setter
    def arguments(self, args):
        self._raw_args = args
        self.assign_fields()

    @property
    def non_empty_args(self):
        return [k for k, v in self.clean_args.items() if v is not None]


class ClientsInterestsRequest(RequestBase):
    __metaclass__ = RequestMeta
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)

    @staticmethod
    def scoring_func(store, ctx, client_ids, date):
        ctx['nclients'] = len(client_ids)
        return {cl: get_interests(store, cl) for cl in client_ids}

    @staticmethod
    def scoring_check():
        return True


class OnlineScoreRequest(RequestBase):
    __metaclass__ = RequestMeta
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def scoring_check(self):
        fields = self.fields
        return (not fields['phone'].isnull_assigned() and not fields['email'].isnull_assigned()) or \
               (not fields['first_name'].isnull_assigned() and not fields['last_name'].isnull_assigned()) or \
               (not fields['gender'].isnull_assigned() and not fields['birthday'].isnull_assigned())

    def scoring_func(self, store, ctx,  **kwargs):
        ctx['has'] = self.non_empty_args
        return {'score': get_score(store, **kwargs) }


class MethodRequest(RequestBase):
    __metaclass__ = RequestMeta
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    method_map = {'online_score': OnlineScoreRequest,
                  'clients_interests': ClientsInterestsRequest}

    def __init__(self, argmnts, ctx, store):
        super(MethodRequest, self).__init__(argmnts)
        method = self.fields['method'].val
        logging.info("Initializing method request with %s" % method)
        arguments = self.fields['arguments'].val
        self.ctx = ctx
        self.store = store
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

    def get_admin_score(self, ctx, store):
        ctx['has'] = self.method_inst.non_empty_args
        return {'score': 42}, OK

    def get_response(self):
        if not self.check_auth():
            logging.error("Wrong credentials provided")
            return 'Wrong Credentials', FORBIDDEN
        elif self.fields_errs:
            fields_errs_str = '\n'.join(self.fields_errs)
            logging.error("Invalid Method request, the following fields have errors: %s" % fields_errs_str)
            return fields_errs_str, INVALID_REQUEST
        elif self.method_err:
            logging.error("Method name provided is wrong: %s" % self.method_err)
            return self.method_err, INVALID_REQUEST
        elif self.method_inst.fields_errs:
            method_inst_field_errs = '\n'.join(self.method_inst.fields_errs)
            logging.error("Invalid method fields: %s" % method_inst_field_errs)
            return method_inst_field_errs, INVALID_REQUEST
        elif self.fields['method'].val == 'online_score' and self.is_admin:
            logging.info("Returning online score for admin user")
            return self.get_admin_score(self.ctx, self.store)
        else:
            logging.info("Returning results for method request")
            return self.method_inst.get_method_score(self.ctx, self.store)


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
    method_request = MethodRequest(request['body'], ctx, store)
    return method_request.get_response()


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
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(filename=opts.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    logging.getLogger().setLevel(logging.DEBUG)
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
