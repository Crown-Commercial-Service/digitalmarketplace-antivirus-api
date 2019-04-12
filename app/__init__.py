from flask import Flask

from dmutils.flask_init import init_app, api_error_handlers

from config import configs


def create_app(config_name):
    application = Flask(__name__)
    application.config['DM_ENVIRONMENT'] = config_name

    init_app(
        application,
        configs[config_name],
        error_handlers=api_error_handlers,
    )

    if not application.config['DM_ANTIVIRUS_API_AUTH_TOKENS']:
        raise Exception("No DM_ANTIVIRUS_API_AUTH_TOKENS provided")

    if not application.config['DM_ANTIVIRUS_API_CALLBACK_AUTH_TOKENS']:
        raise Exception("No DM_ANTIVIRUS_API_CALLBACK_AUTH_TOKENS provided")

    from .metrics import metrics as metrics_blueprint, gds_metrics
    from .main import main as main_blueprint
    from .callbacks import callbacks as callbacks_blueprint
    from .status import status as status_blueprint

    application.register_blueprint(metrics_blueprint)
    application.register_blueprint(main_blueprint)
    application.register_blueprint(callbacks_blueprint, url_prefix='/callbacks')
    application.register_blueprint(status_blueprint)

    gds_metrics.init_app(application)

    return application
