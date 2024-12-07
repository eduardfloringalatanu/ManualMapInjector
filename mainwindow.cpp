#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QFileDialog>
#include <QDir>
#include <QStringList>
#include <Windows.h>
#include <TlHelp32.h>
#include <QStandardItemModel>
#include <QStandardItem>
#include <QSortFilterProxyModel>
#include "injector.h"
#include <QMessageBox>
#include "json.hpp"
#include <fstream>
#include <QCloseEvent>
#include <thread>

class QSortFilterProxyModel2 : public QSortFilterProxyModel {
public:
    void setFilterKeyColumns(const QList<int>& columns) {
        this->columns = columns;
        invalidateFilter();
    }

protected:
    bool filterAcceptsRow(int source_row, const QModelIndex& source_parent) const override {
        for (auto& column : this->columns) {
            QModelIndex index = sourceModel()->index(source_row, column, source_parent);
            QString cellValue = sourceModel()->data(index).toString();

            if (cellValue.contains(filterRegExp()))
                return true;
        }

        return false;
    }

private:
    QList<int> columns;
};

template<typename T>
void read_value(nlohmann::ordered_json& j, std::string key_name, T& output) {
    if (key_name.empty())
        return;

    if (j.dump().find(key_name) == std::string::npos)
        return;

    j.at(key_name).get_to(output);
}

std::fstream modules_list_file_stream;

void MainWindow::closeEvent(QCloseEvent* event) {
    std::vector<std::string> modules_list;

    for (int i = 0; i < ui->listWidget->count(); ++i)
        modules_list.push_back(ui->listWidget->item(i)->text().toStdString());

    nlohmann::ordered_json j;
    j["modules_list"] = modules_list;

    modules_list_file_stream.open((QDir::currentPath() + "/modules_list.json").toStdString(), std::ios::out | std::ios::trunc);

    modules_list_file_stream << j.dump(4);

    modules_list_file_stream.close();

    QWidget::closeEvent(event);
}

QSortFilterProxyModel2* sort_filter_proxy_model;

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::MainWindow) {
    ui->setupUi(this);

    this->setFixedSize(660, 629);

    modules_list_file_stream.open((QDir::currentPath() + "/modules_list.json").toStdString(), std::ios::in);
    nlohmann::ordered_json j = nlohmann::ordered_json::parse(modules_list_file_stream, nullptr, false);

    modules_list_file_stream.close();

    std::vector<std::string> modules_list;
    read_value(j, "modules_list", modules_list);

    for (auto& module : modules_list) {
        if (ui->listWidget->findItems(QString::fromStdString(module), Qt::MatchFixedString).isEmpty())
            ui->listWidget->addItem(QString::fromStdString(module));
    }

    QStandardItemModel* standard_item_model = new QStandardItemModel();

    standard_item_model->setHorizontalHeaderLabels({ "Process name", "Process ID" });

    HANDLE snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot_handle != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 process_entry;
        process_entry.dwSize = sizeof(PROCESSENTRY32);
        BOOL result = Process32First(snapshot_handle, &process_entry);

        int row = 0;

        while (result) {
            standard_item_model->setItem(row, 0, new QStandardItem(process_entry.szExeFile));
            standard_item_model->setItem(row, 1, new QStandardItem(QString::number(process_entry.th32ProcessID)));

            ++row;

            result = Process32Next(snapshot_handle, &process_entry);
        }

        CloseHandle(snapshot_handle);
    }

    sort_filter_proxy_model = new QSortFilterProxyModel2();

    sort_filter_proxy_model->setSourceModel(standard_item_model);
    sort_filter_proxy_model->setFilterKeyColumns({ 0, 1 });
    sort_filter_proxy_model->setFilterCaseSensitivity(Qt::CaseInsensitive);
    sort_filter_proxy_model->setFilterFixedString(ui->lineEdit->text());

    ui->tableView->setModel(sort_filter_proxy_model);
    ui->tableView->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
}

MainWindow::~MainWindow() {
    delete ui;
}

void MainWindow::on_actionAdd_module_triggered() {
    QStringList filenames = QFileDialog::getOpenFileNames(nullptr, "Add module", QDir::currentPath(), "(*.dll)");

    for (auto& filename : filenames) {
        if (ui->listWidget->findItems(filename, Qt::MatchFixedString).isEmpty())
            ui->listWidget->addItem(filename);
    }
}

void MainWindow::on_listWidget_itemDoubleClicked(QListWidgetItem* item) {
    ui->listWidget->removeItemWidget(item);
    delete item;
}

void MainWindow::on_lineEdit_textChanged(const QString& arg1) {
    sort_filter_proxy_model->setFilterFixedString(arg1);
}

void MainWindow::on_pushButton_clicked() {
    if (ui->tableView->selectionModel()->selectedRows().isEmpty())
        return;

    for (int i = 0; i < ui->listWidget->count(); ++i)
        if (!inject_dll(ui->tableView->model()->data(ui->tableView->model()->index(ui->tableView->selectionModel()->selectedRows().first().row(), 1)).toInt(), ui->listWidget->item(i)->text().toLocal8Bit().data())) {
            QString text = QString("Failed to inject \"%1\".").arg(ui->listWidget->item(i)->text().toLocal8Bit().data());
            QMessageBox::critical(nullptr, "Error", text, QMessageBox::Close);
        }
}

void MainWindow::on_actionAbout_triggered() {
    QMessageBox::information(nullptr, "About", "Copyright © 2024 Magister. All rights reserved.", QMessageBox::Close);
}
