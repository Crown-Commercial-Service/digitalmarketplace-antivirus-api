from flask import Blueprint

from app.authentication import requires_authentication

main = Blueprint('main', __name__)

main.before_request(requires_authentication)


from app.main.views import meta, scan
