from functools import partial

from flask import Blueprint

from app.authentication import requires_authentication

callbacks = Blueprint("callbacks", __name__, url_prefix="/callbacks")

callback_authentication_partial = partial(requires_authentication, module="callbacks", scheme="Basic")
callbacks.before_request(callback_authentication_partial)


from app.callbacks.views import sns
