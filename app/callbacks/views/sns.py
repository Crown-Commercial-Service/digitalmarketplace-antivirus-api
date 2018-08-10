from flask import jsonify

from app.callbacks import callbacks


@callbacks.route('/')
@callbacks.route('')
def callbacks_root():
    return jsonify(status='ok'), 200


@callbacks.route("/sns/s3/uploaded", methods=['POST'])
def handle_s3_sns():
    # TODO check SNS signature authenticity
    # TODO if header shows it's a subscription confirmation message:
    # TODO     check it's for the right topic
    # TODO     send a request to provided url, ensuring sufficient logging
    # TODO fetch tags of S3 object version, abort (happily) if scan result found
    # TODO get clamd socket (ping it?)
    # TODO fetch S3 object
    # TODO send to clamd
    # TODO re-check object tags, warn if about to overwrite existing scan result
    # TODO set scan result tag
    # TODO if result bad:
    # TODO     send notify email
    # TODO     if this is (still) current version of object:
    # TODO         find most recent version of object which is tagged "good"
    # TODO         if there is no such version:
    # TODO             upload fail whale?
    # TODO         else copy that version to become new "current" version for this key, ensuring to copy its tags
    # TODO         note the impossibility of doing this without some race conditions
    pass
