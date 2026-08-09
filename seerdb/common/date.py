# SPDX-FileCopyrightText: 2019 Peter Lemenkov <lemenkov@gmail.com>
# SPDX-License-Identifier: MIT

import datetime


class date(datetime.datetime):
    has_timestamp: bool = False
    timestamptz: int | None = None

    def set_timestamp(self) -> None:
        self.has_timestamp = True

    def set_timestamptz(self, Offset: int) -> 'date':
        self.set_timestamp()
        self.timestamptz = Offset
        # datetime is immutable, so shift into UTC by returning a new instance.
        return self - datetime.timedelta(seconds=Offset)
