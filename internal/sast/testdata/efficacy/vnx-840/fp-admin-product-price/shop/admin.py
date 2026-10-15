from flask import request


@admin.post("/products/<pid>")
def update_product(pid):
    product = Product.query.get(pid)
    product.price = request.form["price"]
    product.name = request.form["name"]
    db.session.commit()
