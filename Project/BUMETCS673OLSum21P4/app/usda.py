import requests
from urllib.parse import quote
import json
import yaml
from pyprojroot import here
from statistics import fmean, StatisticsError


def load_cfg():
    projroot = here()
    with open(projroot / "user_config.yml", "r") as ymlfile:
        cfg = yaml.safe_load(ymlfile)
    return cfg


def usda_api_call(search_term: str, cfg: dict):

    print(quote(search_term))
    #if not search_term:
    #raise Exception('No Food Item Entered')

    api_key = cfg["usda"]['api_key']
    api_str = 'https://api.nal.usda.gov/fdc/v1/foods/search?query={}&pageSize=2&api_key={}'\
        .format(quote(search_term.lower()), api_key)

    response = requests.get(api_str, timeout=5)
    json_data = json.loads(response.text)

    return json_data


def extract_avg_calorie_data(json_data):
    nutrient_list_all = json_data['foods']

    cal_list = []
    for item in nutrient_list_all:
        cals = [x for x in item['foodNutrients'] if x['nutrientName'].lower() == 'energy']
        cal_list.append(cals[0]['value'])

    try:
        cal_avg = fmean(cal_list)
    except StatisticsError as e:
        raise Exception('Entered food not found in database') from e

    return cal_avg


#for testing
if __name__ == '__main__':
    print(extract_avg_calorie_data(usda_api_call('noodle', load_cfg())))
