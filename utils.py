def logger(error_scale,string):
    """
    A simple logger function that prints the provided string.
    """
    if error_scale == "warning":
        logo = "[WARN]"
    elif error_scale == "error":
        logo = "[ERROR]"
    elif error_scale == "info":
        logo = "[INFO]"
    else:
        logo = "[]"
    print(logo + " " + string)