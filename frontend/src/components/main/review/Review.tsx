import classes from './Review.module.css'
import { useContext, useEffect, useState } from 'react'
import { contextDb } from '../Main'

function Review() {
    const DataCtx = useContext(contextDb)

    function handleTeacherSubmit(e) {
        e.preventDefault()

        console.log(DataCtx?.teacherRating);
    }

    function handleStudentSubmit(e) {
        e.preventDefault()

        console.log(DataCtx?.studentRating);
        console.log(e.target.comment.value);
    }

    return (
        <div className={classes.container}>
            <h3>Оцінка завдання "{DataCtx?.selectedLab.name}" викладачем</h3>
            <form className={classes.form} onSubmit={handleTeacherSubmit}>
                <span>
                    {[...Array(5)].map((star, index) => {
                        index += 1
                        return (
                            <button
                                type="button"
                                key={index}
                                className={`${classes.star} ${
                                    index <= (DataCtx?.teacherHover || DataCtx?.teacherRating)
                                        ? classes.on
                                        : classes.off
                                }`}
                                onClick={() => {
                                    if (DataCtx?.data.perms === 'teacher') DataCtx?.setTeacherRating(index)
                                }}
                                onMouseEnter={() => {
                                    if (DataCtx?.data.perms === 'teacher') DataCtx?.setTeacherHover(index)
                                }}
                                onMouseLeave={() => {
                                    if (DataCtx?.data.perms === 'teacher')
                                    DataCtx?.setTeacherHover(DataCtx?.teacherRating)
                                }}
                            >
                                <span>&#9733;</span>
                            </button>
                        )
                    })}
                </span>
                {DataCtx?.data.perms === 'teacher' ? (
                    <>
                        <button className={classes.button} type={'submit'}>
                            Оцінити
                        </button>
                    </>
                ) : (
                    <></>
                )}
            </form>
            <h3>Оцінка завдання студентом</h3>
            <form className={classes.form} onSubmit={handleStudentSubmit}>
                <span>
                    {[...Array(5)].map((star, index) => {
                        index += 1
                        return (
                            <button
                                type="button"
                                key={index}
                                className={`${classes.star} ${
                                    index <= (DataCtx?.studentHover || DataCtx?.studentRating)
                                        ? classes.on
                                        : classes.off
                                } ${DataCtx?.data.perms === 'student' ? classes.buttonHover : ''}`}
                                onClick={() => {
                                    if (DataCtx?.data.perms === 'student') DataCtx?.setStudentRating(index)
                                }}
                                onMouseEnter={() => {
                                    if (DataCtx?.data.perms === 'student') DataCtx?.setStudentHover(index)
                                }}
                                onMouseLeave={() => {
                                    if (DataCtx?.data.perms === 'student')
                                        DataCtx?.setStudentHover(DataCtx?.studentRating)
                                }}
                            >
                                <span>&#9733;</span>
                            </button>
                        )
                    })}
                </span>
                {DataCtx?.data.perms === 'student' ? (
                    <>
                        <input
                            name={'comment'}
                            type={'text'}
                            placeholder={'Ваш коментар...'}
                            required
                        />
                        <button className={classes.button} type={'submit'}>
                            Надіслати
                        </button>
                    </>
                ) : (
                    <>
                        <p>
                            {DataCtx?.selectedLab.msg
                                ? `Коментар студента: ${DataCtx?.selectedLab.msg}`
                                : `Студент ще не дав коментаря на це завдання`}
                        </p>
                    </>
                )}
            </form>
        </div>
    )
}

export default Review
