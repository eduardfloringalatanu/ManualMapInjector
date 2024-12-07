#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QListWidgetItem>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    void update();

private slots:
    void on_actionAdd_module_triggered();

    void on_listWidget_itemDoubleClicked(QListWidgetItem *item);

    void on_lineEdit_textChanged(const QString &arg1);

    void on_pushButton_clicked();

    void on_actionAbout_triggered();

private:
    Ui::MainWindow *ui;

protected:
    void closeEvent(QCloseEvent* event);
};
#endif // MAINWINDOW_H
