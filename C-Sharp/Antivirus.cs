using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Forms;
using VirusTotalNET;
using VirusTotalNET.Objects;
using System.Data.SqlClient;




namespace AntivirusForm
{
    public class AntivirusEx
    {
        int viruses;
        string[] virusList = new string[] { "virus", "trojan", "hack", "hacker" }; //Lista de palabras que queremos buscar
        MetodosAuxiliares aux = new MetodosAuxiliares();
        dumps coredump = new dumps();
        VirusTotalSend send;
        List<string> search;
        List<Virus> _listaVirus;
        Eventos eventos;
        Monitor mon;
        Conexion c = new Conexion();

        public AntivirusMain()
        {
            InitializeComponent();
            send = new VirusTotalSend();
            send.RecuperarProcesos();
            dataGridVTResult.DataSource = send._lista;
            dataGridVTResult.Columns[0].Width = 340;
            dataGridView1.Hide();
            mon = new Monitor();
            eventos = new Eventos(mon);
            eventos.Monitorizar();
        }



        private void dataGridVTResult_CellClick(object sender, DataGridViewCellEventArgs e)
        {
            if (dataGridView1.ColumnCount != 0)
            {
                if (dataGridView1.Visible)
                {
                    dataGridView1.DataSource = null;
                    dataGridView1.DataSource = ((VirusTotalAux)dataGridVTResult.CurrentRow.DataBoundItem).resultados;
                    dataGridView1.Refresh();
                    dataGridView1.Update();
                }
            }

        }


        /// <summary>
        /// Select the path to scan
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void manualbtn_Click(object sender, EventArgs e)
        {

            viruses = 0;
            folderBrowserDialog1.ShowDialog();
            if (folderBrowserDialog1.SelectedPath != "")
            {
                search = Directory.GetFiles(@folderBrowserDialog1.SelectedPath, "*.*", System.IO.SearchOption.AllDirectories).ToList();
                totalLbl.Text = "Total Files: " + search.Count.ToString();
                compararPalabras();
                compararHash();
                deletebtn.Enabled = true;
                cuarentenaBtn.Enabled = true;
            }

        }

        /// <summary>
        /// Scan the whole system, disabled, must enable to use
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void fullscanbtn_Click(object sender, EventArgs e)
        {
            search = Directory.GetFiles(@"C:\\", "*.*", System.IO.SearchOption.AllDirectories).ToList();
            totalLbl.Text = "Total Files: " + search.Count.ToString();
            compararPalabras();
            compararHash();
            deletebtn.Enabled = true;
            cuarentenaBtn.Enabled = true;
        }


        private void analizarVTbtn_Click(object sender, EventArgs e)
        {
            List<VirusTotalAux> aux;

            try
            {

                aux = send.send();
                System.Threading.Thread.Sleep(2500);
                dataGridView1.Show();
                dataGridVTResult.DataSource = null;
                dataGridView1.DataSource = null;
                dataGridVTResult.DataSource = aux;
                dataGridView1.DataSource = aux[0].resultados;
                volverBtn.Show();
                analizarVTbtn.Hide();

            }
            catch (Exception ex)
            {
                System.Windows.Forms.MessageBox.Show("Comprueba tu conexión.");

            }

            dataGridVTResult.Refresh();
            dataGridView1.Refresh();

        }

        /// <summary>
        /// Get the hash from the files and compares it with the ones in BD
        /// </summary>
        public void compararHash()
        {
            Conexion c = new Conexion();
            _listaVirus = new List<Virus>();
            _listaVirus = c.RecuperarDatos();
            c.Cerrar();
            foreach (string item in search)
            {
                foreach (Virus _virus in _listaVirus)
                {
                    if (aux.GetMD5HashFromFile(item).Equals(_virus.Hash))
                    {
                        if (!listVirus.Items.Contains(item))
                        {
                            viruses += 1;
                            this.infectedLbl.Text = "Infected Files:  " + viruses;
                            this.infectedLbl.ForeColor = Color.Red;
                            listVirus.Items.Add(item);
                        }
                    }

                }
            }
        }



        /// <summary>
        /// Open the file and search words in it.
        /// </summary>
        public void compararPalabras()
        {
            foreach (string item in search)
            {
                this.lblFolder.Text = item;
                if (item.Contains(".txt") || item.Contains(".pdf") || item.Contains(".doc"))
                {
                    continue;
                }
                else
                {
                    try
                    {
                        StreamReader stream = new StreamReader(item);
                        string read = stream.ReadToEnd();
                        stream.Close();
                        foreach (string str in virusList)
                        {

                            if (Regex.IsMatch(read.ToLower(), str))
                            {
                                if (!listVirus.Items.Contains(item))
                                {
                                    viruses += 1;
                                    this.infectedLbl.Text = "Infected Files:  " + viruses;
                                    this.infectedLbl.ForeColor = Color.Red;
                                    //infectedLbl="Infected Files" + viruses;
                                    listVirus.Items.Add(item);
                                }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        System.Windows.Forms.MessageBox.Show("Ocurrio un error.");
                    }
                }
            }
        }

        /// <summary>
        /// Creates a dump of the process
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void crearDump_Click(object sender, EventArgs e)
        {
            Console.WriteLine(dataGridVTResult.SelectedCells[0].Value.ToString());
            String proceso = dataGridVTResult.SelectedCells[0].Value.ToString();
            string[] words = proceso.Split('\\');
            String proceso1 = words.Last();
            words = proceso1.Split('.');
            Console.WriteLine(words.First());
            coredump.CurrentDomain_UnhandledException(words.First());
        }


        private void volverBtn_Click(object sender, EventArgs e)
        {
            analizarVTbtn.Show();
            dataGridVTResult.DataSource = send._lista;
            dataGridVTResult.Columns[0].Width = 230;
            dataGridView1.Hide();
            volverBtn.Hide();
        }

        private void deletebtn_Click(object sender, EventArgs e)
        {

            List<string> items = listVirus.CheckedItems.Cast<string>().ToList();

            foreach (var item in items)
            {
                // Delete a file by using File class static method... 
                if (System.IO.File.Exists(item.ToString()))
                {
                    // Use a try block to catch IOExceptions, to 
                    // handle the case of the file already being 
                    // opened by another process. 
                    try
                    {
                        this.lblFolder.Text = "Archivos seleccionados Borrados";
                        Console.WriteLine("Borrado");
                        System.IO.File.Delete(item.ToString());
                        listVirus.Items.Remove(item);
                        listVirus.Refresh();
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine(ex.Message);
                        return;
                    }
                }
                Console.WriteLine(item.ToString());
            }
        }


        private void cuarentenaBtn_Click(object sender, EventArgs e)
        {
            List<string> items = listVirus.CheckedItems.Cast<string>().ToList();

            foreach (var item in items)
            {
                string sourceFile = item.ToString();
                string[] words = sourceFile.Split('\\');
                string destinationFile = AppDomain.CurrentDomain.BaseDirectory + "\\cuarentena\\" + words.Last()+".disabled";
                //string destinationFile = @"D:\\cuarentena\\" + words.Last()+".disabled";
                System.IO.File.Move(sourceFile, destinationFile);
                this.lblFolder.Text = "Archivos movidos a cuarentena";
                listVirus.Items.Remove(item);
                listVirus.Refresh();
            }

        }

        private void monitorBtn_Click(object sender, EventArgs e)
        {
            mon.Show();
        }




    }
}
