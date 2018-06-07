from flask import Flask

from dmutils import init_app

from config import configs


def create_app(config_name):
    application = Flask(__name__)
    application.config['DM_ENVIRONMENT'] = config_name

    init_app(
        application,
        configs[config_name],
    )

    if not application.config['DM_AV_AUTH_TOKENS']:
        raise Exception("No DM_AV_AUTH_TOKENS provided")

    from .main import main as main_blueprint
    from .status import status as status_blueprint

    application.register_blueprint(main_blueprint)
    application.register_blueprint(status_blueprint)

    return application
