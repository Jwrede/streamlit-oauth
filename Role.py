from typing import Union, Literal

class Role:
    def __init__(
            self, 
            role_name: str,
            ad_group: str,
            may_see_app: bool = True
        ):
        self.role_name = role_name
        self.ad_group = ad_group
        self.may_see_app = may_see_app
        

no_access_role = Role(
    role_name="no_access",
    ad_group=""
)
