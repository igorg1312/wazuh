/**
 * @file db.cpp
 * @brief Definition of FIM database library.
 * @date 2019-08-28
 *
 * @copyright Copyright (C) 2015-2021 Wazuh, Inc.
 */

#include "dbsync.hpp"
#include "db.hpp"
#include "fimCommonDefs.h"
#include "fimDB.hpp"
#include "fimDBHelper.hpp"
#include "dbFileItem.hpp"

#ifdef WIN32
#include "dbRegistryKey.hpp"
#include "dbRegistryValue.hpp"
#endif

#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Create the statement string to create the dbsync schema.
 *
 * @return std::string Contains the dbsync's schema for FIM db.
 */
const char * CreateStatement()
{
    std::string ret = CREATE_FILE_DB_STATEMENT;
#ifdef WIN32
    ret += CREATE_REGISTRY_KEY_DB_STATEMENT;
    ret += CREATE_REGISTRY_VALUE_DB_STATEMENT;
#endif

    return ret.c_str();
}

#ifndef WIN32
void fim_db_init(int storage,
                 int sync_interval,
                 int file_limit,
                 fim_sync_callback_t sync_callback,
                 logging_callback_t log_callback)
#else
void fim_db_init(int storage,
                 int sync_interval,
                 int file_limit,
                 int value_limit,
                 fim_sync_callback_t sync_callback,
                 logging_callback_t log_callback)
#endif
{
    try
    {
        auto path = (storage == FIM_DB_MEMORY) ? FIM_DB_MEMORY_PATH : FIM_DB_DISK_PATH;

        auto dbsyncHandler = std::make_shared<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, path, CreateStatement());
        auto rsyncHandler = std::make_shared<RemoteSync>();

#ifndef WIN32
        FIMDBHelper::initDB<FIMDB>(sync_interval, file_limit, sync_callback, log_callback, dbsyncHandler, rsyncHandler);
#else
        FIMDBHelper::initDB<FIMDB>(sync_interval, file_limit, value_limit, sync_callback, log_callback, dbsyncHandler,
                                   rsyncHandler);
#endif
    }
    catch (const DbSync::dbsync_error& ex)
    {
        auto errorMessage = "DB error, id: " + std::to_string(ex.id()) + ". " + ex.what();
        log_callback(LOG_ERROR_EXIT, errorMessage.c_str());
    }
}

TXN_HANDLE fim_db_transaction_start(const char* table)
{
    return FIMDBHelper::startDBSyncTxn<FIMDB>(table).handle();
}

FIMDBErrorCodes fim_db_transaction_sync_row(TXN_HANDLE txn_handler, const fim_entry* entry) {
    DBSyncTxn activeTransaction(txn_handler);
    std::unique_ptr<DBItem> syncItem;
    auto retVal = FIMDB_OK;
    try
    {
        if (entry->type == FIM_TYPE_FILE)
        {
            syncItem = std::make_unique<FileItem>(entry);
        }
        else
        {
            syncItem = std::make_unique<FileItem>(entry);

        }
        FIMDBHelper::TxnSyncRow<FIMDB>(activeTransaction, *syncItem.get());
    }
    catch (const DbSync::max_rows_error& ex)
    {
        retVal = FIMDB_FULL;
    }
    catch (const DbSync::dbsync_error& ex)
    {
        auto errorMessage = "DB error, id: " + std::to_string(ex.id()) + ". " + ex.what();
        retVal = FIMDB_ERR;
    }

    return retVal;
}

FIMDBErrorCodes fim_db_transaction_deleted_rows(TXN_HANDLE txn_handler, result_callback_t res_callback) {
    DBSyncTxn activeTransaction(txn_handler);
    auto retVal = FIMDB_OK;
    const auto callback
    {
        [](ReturnTypeCallback result, const nlohmann::json & data)
        {
            // notifyChange(result, data, PACKAGES_TABLE);
        }
    };

    try
    {
        activeTransaction.getDeletedRows(callback);
    }
    catch (const DbSync::dbsync_error& ex)
    {
        auto errorMessage = "DB error, id: " + std::to_string(ex.id()) + ". " + ex.what();
        retVal = FIMDB_ERR;
    }

    return retVal;
}



#ifdef __cplusplus
}
#endif
