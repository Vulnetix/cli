# return jsonify(trace=traceback.format_exc())  -- removed, leaked internals
MESSAGE = "avoid returning traceback.format_exc() to clients"
