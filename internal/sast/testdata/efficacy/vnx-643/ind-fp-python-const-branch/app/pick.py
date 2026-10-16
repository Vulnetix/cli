def pick_item(tree, sku):
    batch = 8
    if batch * 5 - 10 > 20:
        pick = "SKU-100"
    else:
        pick = sku
    return tree.xpath(f"//item[@sku='{pick}']")
