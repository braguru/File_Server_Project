from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.tokens import PasswordResetTokenGenerator
import six

"""
token generation with user id, timestamp and activation of user

six provides utilities for dealing with differences between python versions, such as string types, iterators, meta classes, etc.

"""
class AccountActivationTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return(
            six.text_type(user.pk) + six.text_type(timestamp) + six.text_type(user.is_active)
            )

account_activation_token = AccountActivationTokenGenerator()

