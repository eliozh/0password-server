#! /usr/bin/python
# -*- coding: utf-8 -*-
"""
@File       :   EncJSON.py
@Time       :   20/06/07 17:15
@Author     :   Elio Zhou
"""

import json

from typing import Union, Optional


class EncJSON:
    """
    Encrypted key as JWK format.
    """

    def __init__(self, enc: str, kid: str, data: str, **kwargs: Union[str, int, float, bool, list, tuple, dict]):
        self.enc = enc
        self.kid = kid
        self.data = data
        self.kwargs = kwargs

    def serialize(self, return_str: Optional[bool] = False) -> Union[dict, str]:
        res = {'enc': self.enc, 'kid': self.kid, 'data': self.data}

        for i in self.kwargs:
            res[i] = self.kwargs[i]

        if return_str:
            return json.dumps(res)
        else:
            return res
