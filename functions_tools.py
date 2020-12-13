def get_sorted_list_from_weighted_dict(dictionary):
    weight_to_item = dict()
    all_weights = set()
    for item in dictionary:
        all_weights.add(dictionary[item])
        if not dictionary[item] in weight_to_item:
            weight_to_item[dictionary[item]] = list()
        weight_to_item[dictionary[item]].append(item)
    all_weights = list(all_weights)
    all_weights.sort(reverse=True)
    results = list()
    for weight in all_weights:
        items = weight_to_item[weight]
        items.sort()
        for item in items:
            results.append(item)
    return (results)

def print_debug_message(message):
    print(message)