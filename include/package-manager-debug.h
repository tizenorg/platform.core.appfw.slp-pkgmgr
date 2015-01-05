/*
 * slp-pkgmgr
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
  * Contact: junsuk. oh <junsuk77.oh@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef __PKG_MANAGER_DEBUG_H__
#define __PKG_MANAGER_DEBUG_H__

#include <dlog.h>

#ifndef ERR
#define ERR(fmt, args...) LOGE("[%s:%d] "fmt"\n", __func__, __LINE__, ##args)
#endif

#ifndef DBG
#define DBG(fmt, args...) LOGD("[%s:%d] "fmt"\n", __func__, __LINE__, ##args)
#endif

#ifndef INFO
#define INFO(fmt, args...) LOGI("[%s:%d] "fmt"\n", __func__, __LINE__, ##args)
#endif

#endif  /* __PKG_MANAGER_DEBUG_H__ */
