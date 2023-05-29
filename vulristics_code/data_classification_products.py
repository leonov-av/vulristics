import json

def get_product_data():
    f = open("data/classification/products.json", "r")
    product_data = json.loads(f.read())
    f.close()
    return product_data


