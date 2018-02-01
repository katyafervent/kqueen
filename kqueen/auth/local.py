from .base import BaseAuth
from kqueen.models import User

import bcrypt
import logging

logger = logging.getLogger(__name__)


class LocalAuth(BaseAuth):
    def verify(self, user, password):
        """Implementation of :func:`~kqueen.auth.base.__init__`

        This function tries to find local user and verify password.
        """

        if isinstance(user, User):
            user_password = user.password.encode('utf-8')
            given_password = password

            if bcrypt.checkpw(given_password, user_password):
                return user, None

        return None, "Local authentication failed"
