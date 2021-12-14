/**
 * @file db.hpp
 * @brief Definition of FIM database library.
 * @date 2019-08-28
 *
 * @copyright Copyright (C) 2015-2021 Wazuh, Inc.
 */

#ifndef FIMDB_H
#define FIMDB_H
#include <openssl/evp.h>
#include "fimCommonDefs.h"
#include "commonDefs.h"
#include "syscheck.h"

#ifdef __cplusplus
extern "C" {
#endif


#define FIM_DB_MEMORY_PATH  ":memory:"
#define FIM_DB_DISK_PATH    "queue/fim/db/fim.db"

#define EVP_MAX_MD_SIZE 64

#ifndef WIN32
/**
 * @brief Initialize the FIM database.
 *
 * It will be dbsync the responsible of managing the DB.
 * @param storage storage 1 Store database in memory, disk otherwise.
 * @param sync_interval Interval when the synchronization will be performed.
 * @param file_limit Maximum number of files to be monitored
 * @param sync_callback Callback to send the synchronization messages.
 * @param log_callback Callback to perform logging operations.
 */
void fim_db_init(int storage,
                 int sync_interval,
                 int file_limit,
                 fim_sync_callback_t sync_callback,
                 logging_callback_t log_callback);
#else
/**
 * @brief Initialize the FIM database.
 *
 * It will be dbsync the responsible of managing the DB.
 * @param storage storage 1 Store database in memory, disk otherwise.
 * @param sync_interval Interval when the synchronization will be performed.
 * @param file_limit Maximum number of files to be monitored
 * @param sync_callback Callback to send the synchronization messages.
 * @param log_callback Callback to perform logging operations.
 */
void fim_db_init(int storage,
                 int sync_interval,
                 int file_limit,
                 int value_limit,
                 fim_sync_callback_t sync_callback,
                 logging_callback_t log_callback);
#endif

/**
 * @brief Function that starts a new DBSync transaction.
 *
 * @param table Database table that will be used in the DBSync transaction.
 * @return TXN_HANDLE Transaction handler.
 */
TXN_HANDLE fim_db_transaction_start(const char* table);

/**
 * @brief Function to perform a sync row operation (ADD OR REPLACE).
 *
 * @param txn_handler Handler to an active transaction.
 * @param entry FIM entry to be added/updated.
 *
 * @retval FIMDB_OK on success.
 * @retval FIMDB_FULL if the table limit was reached.
 * @retval FIMDB_ERR on failure.
 */
FIMDBErrorCodes fim_db_transaction_sync_row(TXN_HANDLE txn_handler, const fim_entry* entry);

/**
 * @brief Function to perform the deleted rows operation.
 *
 * @param txn_handler Handler to an active transaction.
 * @param callback Function to be executed for each deleted entry.
 *
 * @retval FIMDB_OK on success.
 * @retval FIMDB_FULL if the table limit was reached.
 * @retval FIMDB_ERR on failure.
 */
FIMDBErrorCodes fim_db_transaction_deleted_rows(TXN_HANDLE txn_handler, result_callback_t callback);

#ifdef __cplusplus
}
#endif // _cplusplus
#endif // FIMDB_H
