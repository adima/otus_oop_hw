import pytest
import api as a

class TestFields(object):
    def test__null_required_error(self):
        field = a.CharField(required=True)
        with pytest.raises(ValueError):
            field.clean(None)
    def test__null_not_required_nullable_ok(self):
        field = a.CharField(required=False, nullable=True)
        res = field.clean(None)
        assert (res, None)

    def test__null_not_required_not_nullable_error(self):
        field = a.CharField(required=False, nullable=False)
        with pytest.raises(ValueError):
            field.clean(None)

    @pytest.mark.parametrize('value', [1, 3.552, True])
    def test__charfield_nonstring_error(self, value):
        charfield = a.CharField()
        with pytest.raises(ValueError):
            charfield.clean(value)

    @pytest.mark.parametrize('value', ['zhazha', 'sfd3532d#@$', '1', str(32342)])
    def test__charfield_string_ok(self, value):
        charfield = a.CharField()
        resp = charfield.clean(value)
        assert (resp, value)

    @pytest.mark.parametrize('value', [89055213443, '+79160953323', '9160953323', 'string'])
    def test__phone_field_wrong_phone_fail(self, value):
        phonefield = a.PhoneField()
        with pytest.raises(ValueError):
            phonefield.clean(value)

    @pytest.mark.parametrize('value', [79055213443, '79160953323', '79160953323'])
    def test__phone_correct_ok(self, value):
        phonefield = a.PhoneField()
        resp = phonefield.clean(value)
        assert (resp, value)

    def test__email_incoorect(self, value):
        pass




