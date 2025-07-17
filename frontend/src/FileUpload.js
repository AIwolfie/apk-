import React, { useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
import axios from 'axios';

function FileUpload({ setScanning, setReport }) {
  const onDrop = useCallback(acceptedFiles => {
    const file = acceptedFiles[0];
    if (file && file.name.endsWith('.apk')) {
      setScanning(true);
      setReport(null);

      const formData = new FormData();
      formData.append('apkfile', file);

      axios.post('http://localhost:5000/scan', formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        }
      }).then(response => {
        setReport(response.data);
      }).catch(error => {
        console.error("Error uploading file:", error);
        alert("Scan failed. See console for details.");
      }).finally(() => {
        setScanning(false);
      });
    } else {
      alert("Please upload a valid .apk file.");
    }
  }, [setScanning, setReport]);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({ onDrop });

  return (
    <div {...getRootProps()} className="upload-box">
      <input {...getInputProps()} />
      {
        isDragActive ?
          <p>Drop the .apk file here ...</p> :
          <p>Drag & drop your .apk file here, or click to select</p>
      }
    </div>
  );
}

export default FileUpload;