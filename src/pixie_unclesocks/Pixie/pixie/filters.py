import re
import operator



class FilterLogic:

    def __init__(self, filter_args):

        self.filter_args = filter_args

        self.operator_map = {
            ">": operator.gt,
            ">=": operator.ge,
            "<": operator.lt,
            "<=": operator.le,
            "==": operator.eq,
            "=": operator.eq,
            "!=": operator.ne,
            "contains": self._contains,
            "!contains": self._not_contains
        }

        self.filter_config = {
            "CONFIDENCE": {
                "extract": lambda ip_abuse_record: ip_abuse_record.get('Raw Abuse Score', 0),
                "cast": int
            },

            "TOTALREPORTS": {
                "extract": lambda ip_abuse_record: ip_abuse_record.get('Total Reports', 0),
                "cast": int
            },

            "ISP": {
                "extract": lambda ip_abuse_record: ip_abuse_record.get('ISP', '').upper(),
                "cast": str
            },

            "COUNTRYCODE": {
                "extract": lambda ip_abuse_record: ip_abuse_record.get('Country Code', '').upper(),
                "cast": str
            },

            "DOMAIN": {
                "extract": lambda ip_abuse_record: ip_abuse_record.get('Domain', '').upper(),
                "cast": str
            },

            "BLACKLISTED": {
                "extract": lambda ip_abuse_record: ip_abuse_record.get('Blacklisted', False),
                "cast": self._bool_cast
            }
        }
        

    @staticmethod
    def _contains(a_string, b_string):
        return b_string.upper() in a_string.upper()
    
    @staticmethod
    def _not_contains(a_string, b_string):
        return b_string.upper() not in a_string.upper()

    @staticmethod
    def _bool_cast(value):

        if value.strip().upper() in ("TRUE", "YES", "1"):
            return True
        elif value.strip().upper() in ("FALSE", "NO", "0"):
            return False
        else:
            raise ValueError(f"ERR-FL05: Invalid value {value} for BLACKLISTED field. Use True/False, Yes/No, or 1/0 only.")


    def build_filter(self):
        
        filter_pattern = re.compile(r'((((?P<filter_key_int>CONFIDENCE|TOTALREPORTS)(?:\s*)?(?P<filter_op_int>>=|<=|==|!=|>|<|=))|((?P<filter_key_str>ISP|COUNTRYCODE|DOMAIN)(?:\s*)?(?P<filter_op_str>contains|!contains))|((?P<filter_key_bl>BLACKLISTED)(?:\s*)?(?P<filter_op_bl>==|=)))(?:\s*)?(?P<filter_value>\S+))', 
                                    re.IGNORECASE)
        if not filter_pattern:
            raise ValueError(f"Invalid filter format {filter}")

        parsed_filters = []

        for filter in self.filter_args:
            filter_match = filter_pattern.fullmatch(filter)
            if not filter_match:
                raise ValueError(f"ERR-FL01: Invalid filter format: '{filter}'. Expected format like 'CONFIDENCE >= 85'.")            

            key = filter_match.group('filter_key_int') or filter_match.group('filter_key_str') or filter_match.group('filter_key_bl')
            op = filter_match.group('filter_op_int') or filter_match.group('filter_op_str') or filter_match.group('filter_op_bl')
            value = filter_match.group('filter_value')

            key_normalized = key.upper()
            config = self.filter_config.get(key_normalized)
            if not config:
                raise ValueError(f"ERR-FL02: Unknown filter key {key_normalized}.")

            extracted = config['extract']
            cast = config['cast']

            try:
                op_func = self.operator_map[op]
            except:
                raise ValueError(f"ERR-FL03: Invalid operator. Use --help option for more information on the available operators.")

            try:
                value = cast(value)
            except:
               raise ValueError(f"ERR-FL04: Invalid cast for value {value}.") 

            parsed_filters.append(lambda ip_absuse_record, op=op_func, value=value, extracted=extracted: op(extracted(ip_absuse_record), value))

        return parsed_filters
    

    def apply_filter(self, ip_list, filters):

        if self.filter_args:
            applied_filters = filters
            filtered_ip_list = [ip for ip in ip_list if all(filter(ip) for filter in applied_filters)]

        else:
            filtered_ip_list = ip_list
        
        return filtered_ip_list