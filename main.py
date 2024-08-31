import tui


def main():
    tui.print_interface()
    data = {'ip': '1.1.0.0', 'type': 'ipv4', 'continent_code': 'AS', 'continent_name': 'Asia', 'country_code': 'CN', 'country_name': 'China', 'region_code': 'FJ', 'region_name': 'Fujian', 'city': 'Fuzhou', 'zip': '350000', 'latitude': 26.062780380249023, 'longitude': 119.29000091552734, 'location': {'geoname_id': 1810821, 'capital': 'Beijing', 'languages': [{'code': 'zh', 'name': 'Chinese', 'native': '中文'}], 'country_flag': 'https://assets.ipstack.com/flags/cn.svg', 'country_flag_emoji': '🇨🇳', 'country_flag_emoji_unicode': 'U+1F1E8 U+1F1F3', 'calling_code': '86', 'is_eu': False}}
    tui.sniff()


if __name__ == '__main__':
    main()
