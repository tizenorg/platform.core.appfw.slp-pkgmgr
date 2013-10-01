/*
 * pkgmgr-debug
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

#ifndef __PKGMGR_DEBUG_H__
#define __PKGMGR_DEBUG_H__

#include <dlog.h>

#define _LOGE(fmt, arg...) LOGE(fmt, ##arg)
#define _LOGD(fmt, arg...) LOGD(fmt, ##arg)


#define COLOR_RED 		"\033[0;31m"
#define COLOR_BLUE 		"\033[0;34m"
#define COLOR_END		"\033[0;m"

#define PKGMGR_DEBUG(fmt, ...)\
	do\
	{\
		LOGD("[%s(): %d]" fmt, __FUNCTION__, __LINE__,##__VA_ARGS__);\
	} while (0)

#define PKGMGR_DEBUG_ERR(fmt, ...)\
	do\
	{\
		LOGE(COLOR_RED"[%s(): %d]" fmt COLOR_END, __FUNCTION__, __LINE__,##__VA_ARGS__);\
	}while (0)

#define PKGMGR_BEGIN() \
	do\
    {\
		LOGD(COLOR_BLUE"[%s(): %d] BEGIN >>>>"COLOR_END, __FUNCTION__ ,__LINE__);\
    } while( 0 )

#define PKGMGR_END() \
	do\
    {\
		LOGD(COLOR_BLUE"[%s(): %d] END <<<<"COLOR_END, __FUNCTION__,__LINE__ );\
    } \
    while( 0 )

#define ret_if(expr) do { \
	if (expr) { \
		PKGMGR_DEBUG_ERR("(%s) ", #expr); \
		PKGMGR_END();\
		return; \
	} \
} while (0)

#define retm_if(expr, fmt, arg...) do { \
	 if (expr) { \
		 PKGMGR_DEBUG_ERR("(%s) "fmt, #expr, ##arg); \
		 PKGMGR_END();\
		 return; \
	 } \
 } while (0)

#define retv_if(expr, val) do { \
		if (expr) { \
			PKGMGR_DEBUG_ERR("(%s) ", #expr); \
			PKGMGR_END();\
			return (val); \
		} \
	} while (0)

#define retvm_if(expr, val, fmt, arg...) do { \
	if (expr) { \
		PKGMGR_DEBUG_ERR("(%s) "fmt, #expr, ##arg); \
		PKGMGR_END();\
		return (val); \
	} \
} while (0)

#define trym_if(expr, fmt, arg...) do { \
			 if (expr) { \
				 PKGMGR_DEBUG_ERR("(%s) "fmt, #expr, ##arg); \
				 goto catch; \
			 } \
		 } while (0)

#define tryvm_if(expr, val, fmt, arg...) do { \
			 if (expr) { \
				 PKGMGR_DEBUG_ERR("(%s) "fmt, #expr, ##arg); \
				 val; \
				 goto catch; \
			 } \
		 } while (0)

#endif  /* __PKGMGR_DEBUG_H__ */
